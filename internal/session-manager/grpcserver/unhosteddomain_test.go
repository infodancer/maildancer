package grpcserver

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/peersignal"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newFallbackServer builds a sessionServer whose router has a fallback agent
// configured, which every other fixture in this package deliberately does not.
//
// That gap is why the bug #221 fixes was never caught: production wires a passwd
// fallback (manager.SetupAuth), the tests wired nil, and the two disagreed about
// what an unhosted-domain attempt was. With a fallback the attempt used to reach
// it, miss, come back ErrUserNotFound, and get banned by rule 1.
func newFallbackServer(t *testing.T, failDelay time.Duration) (*sessionServer, *peerfilter.Filter) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	cfg := peerfilter.Defaults()
	cfg.AbuseWindow = time.Hour
	filter, err := peerfilter.New(cfg, client, nil, nil)
	if err != nil {
		t.Fatalf("peerfilter.New: %v", err)
	}

	provider := &wiringDomainProvider{d: &domain.Domain{
		Name:      "example.com",
		AuthAgent: timingAuthAgent{},
	}}
	router := domain.NewAuthRouter(provider, fallbackAuthAgent{})
	t.Cleanup(func() { _ = router.Close() })

	mgr := manager.New(&config.Config{}, router, provider, nil)
	t.Cleanup(mgr.Close)

	return &sessionServer{mgr: mgr, filter: filter, authFailDelay: failDelay}, filter
}

// fallbackAuthAgent stands in for the passwd agent production configures as the
// router fallback. It knows one fully-qualified legacy user, which is a
// supported passwd-file configuration.
type fallbackAuthAgent struct{}

func (fallbackAuthAgent) Authenticate(_ context.Context, username, password string) (*auth.AuthSession, error) {
	if username == "legacy@old.example" && password == "correct" {
		return &auth.AuthSession{User: &auth.User{Username: username, Mailbox: username}}, nil
	}
	if username == "legacy@old.example" {
		return nil, autherrors.ErrAuthFailed
	}
	return nil, autherrors.ErrUserNotFound
}

func (fallbackAuthAgent) UserExists(_ context.Context, username string) (bool, error) {
	return username == "legacy@old.example", nil
}

func (fallbackAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
}

func (fallbackAuthAgent) Close() error { return nil }

// TestLogin_UnhostedDomainIsCountedNotBanned is the fix for a live false
// positive. Before #221 this attempt banned the address on sight, because the
// unhosted domain fell through to the fallback agent and came back "user not
// found" -- indistinguishable from rule 1's real case. Any domain migrated off
// this server would have had its former users' addresses banned as their stale
// clients retried.
func TestLogin_UnhostedDomainIsCountedNotBanned(t *testing.T) {
	srv, filter := newFallbackServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.5"

	_, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "someone@notourdomain.test",
		Password: "whatever",
		ClientIp: ip,
	})
	if err == nil {
		t.Fatal("expected the login to fail")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("status = %v, want Unauthenticated: the client must learn nothing", got)
	}

	if v := filter.Check(ctx, ip, true); v.Banned {
		t.Error("banned for naming a domain we do not host; a migrated domain's " +
			"stale clients would be locked out on their first attempt")
	}

	// Counted, though -- otherwise there is no evidence it happened at all.
	entries, err := filter.ListAbuse(ctx)
	if err != nil {
		t.Fatalf("ListAbuse: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Signal == peersignal.UnhostedDomain && e.Prefix == ip {
			found = true
			if e.Count != 1 {
				t.Errorf("unhosted_domain count = %d, want 1", e.Count)
			}
			if e.Threshold != 0 {
				t.Errorf("unhosted_domain threshold = %d, want 0: it must not "+
					"ban on its own", e.Threshold)
			}
		}
	}
	if !found {
		t.Errorf("no unhosted_domain signal recorded; got %+v", entries)
	}
}

// TestLogin_HostedDomainMissingUserStillBans is the non-regression: rule 1 is
// the rule that catches the measured attack, and narrowing it was not the point.
func TestLogin_HostedDomainMissingUserStillBans(t *testing.T) {
	srv, filter := newFallbackServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.6"

	if _, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "nosuchuser@example.com",
		Password: "whatever",
		ClientIp: ip,
	}); err == nil {
		t.Fatal("expected the login to fail")
	}

	if v := filter.Check(ctx, ip, true); !v.Banned {
		t.Error("a nonexistent account on a hosted domain must still ban on the first attempt")
	}
}

// TestLogin_UnhostedDomainDoesNotStealTheWrongPasswordCase guards the case that
// made the naive fix wrong. auth/passwd keys its user map on the exact string from the
// file, so a literal user@legacy.example line is a working configuration -- but
// only where no domains are configured, which is the drop-in host the fallback
// exists for. Here domains *are* configured, so the attempt is reclassified
// rather than reaching the fallback, and the wrong-password case must not
// become an abuse signal either way.
func TestLogin_UnhostedDomainDoesNotStealTheWrongPasswordCase(t *testing.T) {
	srv, filter := newFallbackServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.7"

	// legacy@old.example names an unhosted domain on a server that hosts
	// example.com, so it is reclassified before the fallback sees it.
	if _, err := srv.Login(ctx, &smpb.LoginRequest{
		Username: "legacy@old.example",
		Password: "correct",
		ClientIp: ip,
	}); err == nil {
		t.Fatal("expected failure: a configured server does not honour legacy " +
			"unqualified-host authentication")
	}

	// Still counted, still not banned.
	if v := filter.Check(ctx, ip, true); v.Banned {
		t.Error("banned rather than counted")
	}
}

// TestLogin_UnhostedDomainRespectsTheFailDeadline keeps the timing property.
// Reclassifying happens before the fallback runs, so this path skips the decoy
// argon2id verify and is fast; the absolute deadline is what hides that, and it
// is the only thing that does.
func TestLogin_UnhostedDomainRespectsTheFailDeadline(t *testing.T) {
	const delay = 300 * time.Millisecond
	srv, _ := newFallbackServer(t, delay)

	start := time.Now()
	if _, err := srv.Login(context.Background(), &smpb.LoginRequest{
		Username: "someone@notourdomain.test",
		Password: "whatever",
		ClientIp: "203.0.113.8",
	}); err == nil {
		t.Fatal("expected the login to fail")
	}
	if elapsed := time.Since(start); elapsed < delay {
		t.Errorf("answered in %v, before the %v deadline: the unhosted-domain "+
			"path skips the password hash and would be distinguishable", elapsed, delay)
	}
}
