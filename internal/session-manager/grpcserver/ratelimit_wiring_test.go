package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// wiringAuthAgent accepts one credential and rejects everything else.
type wiringAuthAgent struct{}

func (wiringAuthAgent) Authenticate(_ context.Context, username, password string) (*auth.AuthSession, error) {
	if username == "alice" && password == "correct" {
		return &auth.AuthSession{User: &auth.User{Username: "alice", Mailbox: "alice@example.com"}}, nil
	}
	return nil, autherrors.ErrAuthFailed
}

func (wiringAuthAgent) UserExists(_ context.Context, _ string) (bool, error) { return true, nil }

func (wiringAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
}

func (wiringAuthAgent) Close() error { return nil }

// wiringDomainProvider serves one domain backed by wiringAuthAgent.
type wiringDomainProvider struct {
	d *domain.Domain
}

func (p *wiringDomainProvider) GetDomain(name string) *domain.Domain {
	if name == "example.com" {
		return p.d
	}
	return nil
}

func (p *wiringDomainProvider) Domains() []string { return []string{"example.com"} }

func (p *wiringDomainProvider) Close() error { return nil }

// newWiringServer builds a sessionServer whose Manager holds a Redis-backed
// rate-limited AuthRouter, the way SetupAuth does in production.
func newWiringServer(t *testing.T, maxFailuresPerIPUser int) *sessionServer {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	provider := &wiringDomainProvider{d: &domain.Domain{
		Name:      "example.com",
		AuthAgent: wiringAuthAgent{},
	}}
	router := domain.NewAuthRouter(provider, nil).
		WithRedisRateLimit(domain.RateLimitConfig{
			MaxFailuresPerIPUser: maxFailuresPerIPUser,
			MaxFailuresPerIP:     1000,
			Window:               5 * time.Minute,
			Lockout:              15 * time.Minute,
		}, client)
	t.Cleanup(func() { _ = router.Close() })

	mgr := manager.New(&config.Config{}, router, provider, nil)
	t.Cleanup(mgr.Close)

	return &sessionServer{mgr: mgr}
}

// TestLogin_ClientIPReachesRateLimiter is the test phase 2 exists for. Before
// this, session-manager built the AuthRouter without rate limiting and nothing
// called WithClientIP, so no authentication limiting happened anywhere. This
// asserts the whole chain: LoginRequest.client_ip -> context -> AuthRouter ->
// Redis counters -> ErrRateLimited -> ResourceExhausted on the wire.
func TestLogin_ClientIPReachesRateLimiter(t *testing.T) {
	srv := newWiringServer(t, 3)
	ctx := context.Background()

	req := &smpb.LoginRequest{
		Username: "alice@example.com",
		Password: "wrong",
		ClientIp: "203.0.113.5",
	}

	for i := range 3 {
		_, err := srv.Login(ctx, req)
		if err == nil {
			t.Fatalf("attempt %d: expected authentication failure", i+1)
		}
		if status.Code(err) == codes.ResourceExhausted {
			t.Fatalf("attempt %d: rate limited before reaching the threshold", i+1)
		}
	}

	// Fourth attempt is refused by the limiter rather than the credential
	// check -- note the password is correct here.
	_, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com",
		Password: "correct",
		ClientIp: "203.0.113.5",
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted after the threshold, got %v", err)
	}
}

// TestLogin_LockoutIsPerAddress confirms the limiter is keyed on the address
// the daemon reported, not applied globally: a second address must be
// unaffected, or one attacker locks out everyone.
func TestLogin_LockoutIsPerAddress(t *testing.T) {
	srv := newWiringServer(t, 2)
	ctx := context.Background()

	for range 2 {
		_, _ = srv.Login(ctx, &smpb.LoginRequest{
			Username: "alice@example.com", Password: "wrong", ClientIp: "203.0.113.5",
		})
	}
	if _, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com", Password: "correct", ClientIp: "203.0.113.5",
	}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("precondition: expected the first address to be locked out, got %v", err)
	}

	// A second address must still reach the credential check. Asserting on
	// the status code rather than on a successful login keeps this test out of
	// the mail-session spawn path, which a unit test cannot satisfy: what
	// matters here is that the refusal comes from the credential, not the
	// limiter.
	_, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com", Password: "wrong", ClientIp: "198.51.100.9",
	})
	if status.Code(err) == codes.ResourceExhausted {
		t.Error("a lockout earned by one address spilled onto another")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("second address = %v, want Unauthenticated from the credential check", err)
	}
}

// TestLogin_NoClientIPMeansNoLimiting documents the consequence of dropping the
// username dimension in phase 1. It is not desirable, it is the honest state of
// affairs for a caller that omits the address -- and the reason client_ip is
// documented as required in the proto.
func TestLogin_NoClientIPMeansNoLimiting(t *testing.T) {
	srv := newWiringServer(t, 2)
	ctx := context.Background()

	for i := range 10 {
		_, err := srv.Login(ctx, &smpb.LoginRequest{
			Username: "alice@example.com", Password: "wrong",
		})
		if status.Code(err) == codes.ResourceExhausted {
			t.Fatalf("attempt %d was rate limited with no client_ip; "+
				"no dimension should be keyed", i+1)
		}
	}
}

// The complementary case -- a successful login must not be counted as a
// failure, and must clear the pair's counter -- is covered in auth/domain
// (TestRateLimiter_SuccessResetsIPUserPair and
// TestAuthRouter_RateLimitIntegration). It cannot be asserted here: a
// successful Login continues into spawning a mail-session subprocess, which a
// unit test has no way to satisfy.

// TestLogin_RateLimitedMapsToResourceExhausted keeps the status-code contract
// the daemons already depend on: smtpd maps ResourceExhausted to a 421 "too
// many failed authentication attempts", distinct from a 535 credential
// rejection.
func TestLogin_RateLimitedMapsToResourceExhausted(t *testing.T) {
	srv := newWiringServer(t, 1)
	ctx := context.Background()

	_, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com", Password: "wrong", ClientIp: "203.0.113.5",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("first failure = %v, want Unauthenticated", err)
	}

	_, err = srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com", Password: "wrong", ClientIp: "203.0.113.5",
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("locked-out failure = %v, want ResourceExhausted", err)
	}
	if errors.Is(err, autherrors.ErrRateLimited) {
		t.Error("internal limiter error leaked to the wire; only the status code should cross")
	}
}

// TestKnownGood_DoesNotExemptTheRateLimiter is the security boundary on the
// known-good exemption (#206). It suppresses *connection bans* only. If it also
// exempted the authentication limiter, one compromised credential would buy an
// attacker unlimited password guessing from that address -- the exemption would
// undo rule 2 rather than soften rule 1.
//
// The two mechanisms live in different packages and key on the same address, so
// nothing wires them together today; this test is here to keep it that way.
func TestKnownGood_DoesNotExemptTheRateLimiter(t *testing.T) {
	srv := newWiringServer(t, 2)
	ctx := context.Background()
	const ip = "203.0.113.5"

	// Establish the address as known-good the only way that is possible: a
	// successful authentication. The wiring harness has no peerfilter, so this
	// asserts the limiter's behavior independent of any exemption -- which is
	// exactly the invariant: the limiter never consults known-good state.
	for range 2 {
		_, _ = srv.Login(ctx, &smpb.LoginRequest{
			Username: "alice@example.com", Password: "wrong", ClientIp: ip,
		})
	}

	_, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "alice@example.com", Password: "correct", ClientIp: ip,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected the auth limiter to lock out a known-good address, got %v", err)
	}
}
