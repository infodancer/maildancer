package grpcserver

import (
	"context"
	"errors"
	"log/slog"

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
}

func (s *sessionServer) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
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
		if errors.Is(err, autherrors.ErrRateLimited) {
			// ResourceExhausted is what the daemons already map to a
			// protocol-level "too many attempts" response.
			return nil, status.Error(codes.ResourceExhausted, "too many failed attempts")
		}
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
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
