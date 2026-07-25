package grpcserver

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sessionServer struct {
	smpb.UnimplementedSessionServiceServer
	mgr    *manager.Manager
	filter *peerfilter.Filter
	// authFailDelay is the uniform response deadline for failed
	// authentications. Zero disables it.
	authFailDelay time.Duration
}

func (s *sessionServer) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	// Taken before any work, so the failure deadline below is measured from
	// when the credentials arrived rather than added to however long the
	// attempt took.
	received := time.Now()

	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	// The client IP travels in the context rather than through Login's
	// signature, which is what domain.WithClientIP exists for: it reaches
	// AuthenticateWithDomain, where every rate-limit dimension is keyed on it.
	// Without it there is no limiting at all (#206).
	ctx = domain.WithClientIP(ctx, req.ClientIp)

	result, err := s.mgr.Login(ctx, req.Username, req.Password)
	if err != nil {
		slog.Warn("login failed",
			"username", req.Username, "client_ip", req.ClientIp, "error", err)

		// Rule 1 (#206): an attempt against an account that does not exist is a
		// first-attempt hostile signal. No legitimate client authenticates as a
		// nonexistent account -- a real user's client has a real username
		// configured in it -- so this bans on N=1 rather than counting. It is
		// the only rule that catches the measured attack, where 41 of 59
		// addresses made exactly one attempt.
		if errors.Is(err, autherrors.ErrUserNotFound) && req.ClientIp != "" {
			if berr := s.filter.Ban(ctx, req.ClientIp, "nonexistent_account"); berr != nil {
				slog.Error("failed to ban peer for nonexistent-account attempt",
					"client_ip", req.ClientIp, "error", berr)
			}
		}

		// Hold every failure to a common deadline before answering. The paths
		// above diverge sharply -- one bans the peer and skipped the password
		// hash, the other did the full verify -- and that difference is exactly
		// what must not be observable.
		s.awaitFailDeadline(ctx, received)

		if errors.Is(err, autherrors.ErrRateLimited) {
			// ResourceExhausted is what the daemons already map to a
			// protocol-level "too many attempts" response.
			return nil, status.Error(codes.ResourceExhausted, "too many failed attempts")
		}
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}

	// A successful authentication marks the address known-good, which exempts
	// it from connection-level bans (#206). Reaching this point means a real
	// account authenticated and a session was established -- inbound SMTP never
	// authenticates, so mail reception cannot mark an address good.
	//
	// Failure is logged and ignored: losing the mark costs an exemption, not a
	// working login, and refusing a successful authentication over it would be
	// absurd.
	if req.ClientIp != "" {
		if err := s.filter.RecordGood(ctx, req.ClientIp); err != nil {
			slog.Warn("failed to record known-good peer",
				"client_ip", req.ClientIp, "error", err)
		}
	}

	return &smpb.LoginResponse{
		SessionToken:    result.Token,
		Mailbox:         result.Mailbox,
		Extension:       result.Extension,
		MaxSendsPerHour: int32(result.MaxSendsPerHour),
	}, nil
}

func (s *sessionServer) ValidateRecipient(ctx context.Context, req *smpb.ValidateRecipientRequest) (*smpb.ValidateRecipientResponse, error) {
	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address required")
	}

	domainIsLocal, userExists, deferRejection, err := s.mgr.ValidateRecipient(ctx, req.Address)
	if err != nil {
		slog.Warn("validate recipient failed", "address", req.Address, "error", err)
		return nil, status.Errorf(codes.Internal, "validate recipient: %v", err)
	}

	return &smpb.ValidateRecipientResponse{
		DomainIsLocal:  domainIsLocal,
		UserExists:     userExists,
		DeferRejection: deferRejection,
	}, nil
}

// awaitFailDeadline blocks until authFailDelay has elapsed since received.
//
// An absolute deadline, not a sleep appended to the work. Sleeping for a fixed
// duration after the attempt leaves the attempt's own cost visible in the
// total, and the two failure paths cost very different amounts: a nonexistent
// account skips the password hash (the decoy verify in auth/passwd narrows that
// gap but does not close it, and a ban write adds Redis latency on one side
// only). Releasing both at the same offset from a common start makes the
// remaining difference unobservable.
//
// Returns early if the client goes away; there is nobody left to mislead, and
// holding the goroutine would only help an attacker who hangs up on purpose.
func (s *sessionServer) awaitFailDeadline(ctx context.Context, received time.Time) {
	if s.authFailDelay <= 0 {
		return
	}
	remaining := s.authFailDelay - time.Since(received)
	if remaining <= 0 {
		// The attempt already took longer than the deadline. Nothing to add --
		// and nothing to subtract either, which is why the decoy verify matters:
		// past the deadline, timing reflects the work itself.
		return
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// CheckPeer answers the dispatchers' accept-time ban check. It is the hot path
// of the peer filter -- one call per accepted connection, before any protocol
// work -- so it does exactly one Redis lookup and nothing else.
//
// A missing or unparseable address is an allow, not an error: the caller cannot
// usefully act on a failure here, and refusing connections because the gate is
// confused is the failure mode the whole design avoids.
func (s *sessionServer) CheckPeer(ctx context.Context, req *smpb.CheckPeerRequest) (*smpb.CheckPeerResponse, error) {
	if req.Ip == "" {
		return &smpb.CheckPeerResponse{}, nil
	}

	verdict := s.filter.Check(ctx, req.Ip)
	return &smpb.CheckPeerResponse{
		Banned:   verdict.Banned,
		TarpitMs: verdict.Tarpit.Milliseconds(),
		Reason:   verdict.Reason,
	}, nil
}

// ReportPeer records an abuse signal a handler observed. Failures are logged
// and swallowed: losing an abuse count is not worth failing the caller's
// connection, and the handler has nothing useful to do with the error.
func (s *sessionServer) ReportPeer(ctx context.Context, req *smpb.ReportPeerRequest) (*smpb.ReportPeerResponse, error) {
	if req.Ip == "" || req.Signal == "" {
		return nil, status.Error(codes.InvalidArgument, "ip and signal required")
	}

	if err := s.filter.Report(ctx, req.Ip, req.Signal); err != nil {
		slog.Warn("peer abuse report failed",
			"peer", req.Ip, "signal", req.Signal, "error", err)
	}
	return &smpb.ReportPeerResponse{}, nil
}

func (s *sessionServer) Logout(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	if req.SessionToken == "" {
		return nil, status.Error(codes.InvalidArgument, "session_token required")
	}

	if err := s.mgr.Logout(ctx, req.SessionToken); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	return &smpb.LogoutResponse{}, nil
}
