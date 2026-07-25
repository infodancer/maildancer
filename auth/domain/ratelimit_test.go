package domain

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// newTestLimiter builds a limiter over a memLimitStore with a controllable
// clock, returning both plus a function to advance time.
func newTestLimiter(cfg RateLimitConfig) (*authRateLimiter, func(time.Duration)) {
	store := newMemLimitStore()
	now := time.Now()
	store.now = func() time.Time { return now }
	advance := func(d time.Duration) { now = now.Add(d) }
	return newAuthRateLimiter(cfg, store), advance
}

func TestWithClientIP(t *testing.T) {
	ctx := context.Background()
	if ip := clientIPFromContext(ctx); ip != "" {
		t.Errorf("expected empty IP from bare context, got %q", ip)
	}

	ctx = WithClientIP(ctx, "192.168.1.1")
	if ip := clientIPFromContext(ctx); ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %q", ip)
	}
}

func TestRateLimiter_IPUserLimit(t *testing.T) {
	rl, advance := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100, // high so we only trigger per-pair
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()
	ip := "10.0.0.1"
	user := "alice@example.com"

	// 2 failures -- not yet limited.
	rl.recordFailure(ctx, ip, user)
	rl.recordFailure(ctx, ip, user)
	if rl.isLimited(ctx, ip, user) {
		t.Fatal("should not be limited after 2 failures")
	}

	// 3rd failure triggers lockout.
	rl.recordFailure(ctx, ip, user)
	if !rl.isLimited(ctx, ip, user) {
		t.Fatal("should be limited after 3 failures")
	}

	// Different IP, same user -- not limited: there is no username dimension.
	if rl.isLimited(ctx, "10.0.0.2", user) {
		t.Fatal("different IP should not be limited by per-pair limit")
	}

	// Same IP, different user -- not limited.
	if rl.isLimited(ctx, ip, "bob@example.com") {
		t.Fatal("different user should not be limited by per-pair limit")
	}

	// After lockout expires, no longer limited.
	advance(16 * time.Minute)
	if rl.isLimited(ctx, ip, user) {
		t.Fatal("should not be limited after lockout expires")
	}
}

func TestRateLimiter_PerIPLimit(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 100, // high so we only trigger per-IP
		MaxFailuresPerIP:     3,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()
	ip := "10.0.0.1"

	// Failures against different usernames count toward the per-IP total.
	rl.recordFailure(ctx, ip, "alice@example.com")
	rl.recordFailure(ctx, ip, "bob@example.com")
	rl.recordFailure(ctx, ip, "carol@example.com")

	// Any username from this IP is now locked out.
	if !rl.isLimited(ctx, ip, "dave@example.com") {
		t.Fatal("should be per-IP limited after 3 failures")
	}

	// A different IP is unaffected.
	if rl.isLimited(ctx, "10.0.0.2", "dave@example.com") {
		t.Fatal("different IP should not be limited")
	}
}

// TestRateLimiter_NoUsernameDimension is the denial-of-service regression
// guard for #206: failures against one username from many source addresses
// must never lock that username out globally. The measured attack was spread
// across 59 addresses, so a username-keyed lockout would let an attacker
// disable any known account for the price of a handful of requests.
func TestRateLimiter_NoUsernameDimension(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     3,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()
	user := "alice@example.com"

	// One failure each from many distinct addresses: below both thresholds
	// for every individual address, but 20 failures against the username.
	// This is the shape of the measured spray -- median one attempt per IP.
	for i := range 20 {
		rl.recordFailure(ctx, fmt.Sprintf("10.0.0.%d", i+1), user)
	}

	// A fresh address must still be able to authenticate as that user.
	if rl.isLimited(ctx, "192.168.1.1", user) {
		t.Fatal("username locked out across addresses: reintroduces the DoS vector")
	}
}

// TestRateLimiter_NoClientIPDisablesLimiting pins the consequence of dropping
// the username dimension: with no IP there is nothing left to key on, so no
// limiting happens. This is deliberate, and it is why callers must set
// WithClientIP -- a caller that forgets silently gets no protection.
func TestRateLimiter_NoClientIPDisablesLimiting(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     3,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()

	for range 10 {
		rl.recordFailure(ctx, "", "alice@example.com")
	}
	if rl.isLimited(ctx, "", "alice@example.com") {
		t.Fatal("limiter fired without a client IP; no dimension should be keyed")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl, advance := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		Window:               5 * time.Minute,
		Lockout:              1 * time.Minute,
	})
	ctx := context.Background()
	ip := "10.0.0.1"
	user := "alice@example.com"

	rl.recordFailure(ctx, ip, user)
	rl.recordFailure(ctx, ip, user)

	// Advance past the window: the counter's TTL expires, so the next failure
	// starts a fresh window rather than tipping the threshold.
	advance(6 * time.Minute)

	rl.recordFailure(ctx, ip, user)
	if rl.isLimited(ctx, ip, user) {
		t.Fatal("should not be limited; the failure counter expired with its TTL")
	}
}

func TestRateLimiter_SuccessResetsIPUserPair(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()
	ip := "10.0.0.1"
	user := "alice@example.com"

	rl.recordFailure(ctx, ip, user)
	rl.recordFailure(ctx, ip, user)
	rl.recordSuccess(ctx, ip, user)

	// 2 more failures -- under the threshold again, because success cleared it.
	rl.recordFailure(ctx, ip, user)
	rl.recordFailure(ctx, ip, user)
	if rl.isLimited(ctx, ip, user) {
		t.Fatal("should not be limited; success should have reset the pair counter")
	}
}

// TestRateLimiter_SuccessKeepsPerIPCounter guards the asymmetry in
// recordSuccess: one account authenticating must not reset the per-IP counter,
// or an attacker with one valid credential clears the limit protecting every
// other account behind the same address.
func TestRateLimiter_SuccessKeepsPerIPCounter(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 100,
		MaxFailuresPerIP:     3,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()
	ip := "10.0.0.1"

	rl.recordFailure(ctx, ip, "alice@example.com")
	rl.recordFailure(ctx, ip, "bob@example.com")
	rl.recordSuccess(ctx, ip, "carol@example.com")
	rl.recordFailure(ctx, ip, "dave@example.com")

	if !rl.isLimited(ctx, ip, "eve@example.com") {
		t.Fatal("per-IP counter was reset by an unrelated success")
	}
}

// TestRateLimiter_TTLExpiryReclaimsEntries replaces the old cleanup-goroutine
// test: expiry is now the store's job, so entries must disappear on their own
// once both the window and the lockout have passed. Nothing sweeps.
func TestRateLimiter_TTLExpiryReclaimsEntries(t *testing.T) {
	store := newMemLimitStore()
	now := time.Now()
	store.now = func() time.Time { return now }
	rl := newAuthRateLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     3,
		Window:               5 * time.Minute,
		Lockout:              1 * time.Minute,
	}, store)
	ctx := context.Background()

	rl.recordFailure(ctx, "10.0.0.1", "alice@example.com")
	if store.size() == 0 {
		t.Fatal("expected stored counters after a failure")
	}

	now = now.Add(10 * time.Minute)
	if n := store.size(); n != 0 {
		t.Errorf("expected all entries expired, got %d", n)
	}
}

// errLimitStore fails every operation, to exercise the fail-open path.
type errLimitStore struct{}

var errStoreDown = errors.New("store unavailable")

func (errLimitStore) incr(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, errStoreDown
}
func (errLimitStore) exists(_ context.Context, _ string) (bool, error) { return false, errStoreDown }
func (errLimitStore) set(_ context.Context, _ string, _ time.Duration) error {
	return errStoreDown
}
func (errLimitStore) del(_ context.Context, _ ...string) error { return errStoreDown }

// TestRateLimiter_FailsOpenOnStoreError pins the fail-open decision: a Redis
// outage must not lock out legitimate users. Failing closed would hand the
// attacker the same outcome they are trying to produce, and the outage is
// already visible in the warn logs.
func TestRateLimiter_FailsOpenOnStoreError(t *testing.T) {
	rl := newAuthRateLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 1,
		MaxFailuresPerIP:     1,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}, errLimitStore{})
	ctx := context.Background()

	// Recording must not panic even though every call fails.
	rl.recordFailure(ctx, "10.0.0.1", "alice@example.com")
	rl.recordSuccess(ctx, "10.0.0.1", "alice@example.com")

	if rl.isLimited(ctx, "10.0.0.1", "alice@example.com") {
		t.Fatal("limiter failed closed on a store error; should fail open")
	}
}

// TestRateLimiter_ZeroThresholdDisablesDimension covers the config edge: a
// zero or negative threshold means "no limit on this dimension" rather than
// "lock out on the first failure".
func TestRateLimiter_ZeroThresholdDisablesDimension(t *testing.T) {
	rl, _ := newTestLimiter(RateLimitConfig{
		MaxFailuresPerIPUser: 0,
		MaxFailuresPerIP:     0,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	ctx := context.Background()

	for range 50 {
		rl.recordFailure(ctx, "10.0.0.1", "alice@example.com")
	}
	if rl.isLimited(ctx, "10.0.0.1", "alice@example.com") {
		t.Fatal("zero threshold should disable the dimension, not lock out")
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.MaxFailuresPerIPUser <= 0 || cfg.MaxFailuresPerIP <= 0 {
		t.Errorf("default thresholds must be positive, got %+v", cfg)
	}
	if cfg.MaxFailuresPerIPUser >= cfg.MaxFailuresPerIP {
		t.Errorf("per-pair threshold should be tighter than per-IP, got %+v", cfg)
	}
	if cfg.Window <= 0 || cfg.Lockout <= 0 {
		t.Errorf("default durations must be positive, got %+v", cfg)
	}
}

// TestAuthRouter_RateLimitIntegration tests rate limiting through the full
// AuthRouter.AuthenticateWithDomain path.
func TestAuthRouter_RateLimitIntegration(t *testing.T) {
	agent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			if username == "alice" && password == "correct" {
				return &auth.AuthSession{User: &auth.User{Username: "alice"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {Name: "example.com", AuthAgent: agent},
		},
	}

	router := NewAuthRouter(provider, nil)
	router.WithRateLimit(RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	})
	defer func() { _ = router.Close() }()

	ctx := WithClientIP(context.Background(), "10.0.0.1")

	// 3 failed attempts.
	for i := range 3 {
		_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
		if err == nil {
			t.Fatal("expected auth failure")
		}
		if errors.Is(err, autherrors.ErrRateLimited) {
			t.Fatalf("should not be rate limited on attempt %d", i+1)
		}
	}

	// 4th attempt -- should be rate limited, even with the correct password.
	_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "correct")
	if !errors.Is(err, autherrors.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}

	// Different IP can still authenticate.
	ctx2 := WithClientIP(context.Background(), "10.0.0.2")
	result, err := router.AuthenticateWithDomain(ctx2, "alice@example.com", "correct")
	if err != nil {
		t.Fatalf("expected success from different IP, got %v", err)
	}
	if result.Session.User.Username != "alice" {
		t.Errorf("expected alice, got %q", result.Session.User.Username)
	}
}

// TestAuthRouter_NoRateLimitByDefault verifies that a router without
// WithRateLimit allows unlimited attempts (backward compatible).
func TestAuthRouter_NoRateLimitByDefault(t *testing.T) {
	agent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, _, _ string) (*auth.AuthSession, error) {
			return nil, autherrors.ErrAuthFailed
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {Name: "example.com", AuthAgent: agent},
		},
	}

	router := NewAuthRouter(provider, nil)
	ctx := WithClientIP(context.Background(), "10.0.0.1")

	// 100 failed attempts -- should never get ErrRateLimited.
	for i := range 100 {
		_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
		if errors.Is(err, autherrors.ErrRateLimited) {
			t.Fatalf("rate limited on attempt %d without WithRateLimit", i+1)
		}
	}
}

// TestAuthRouter_WithRedisRateLimitNilClientFallsBack verifies that a nil Redis
// client falls back to in-process limiting rather than silently disabling
// protection -- a misconfigured Redis URL must not turn the limiter off.
func TestAuthRouter_WithRedisRateLimitNilClientFallsBack(t *testing.T) {
	agent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, _, _ string) (*auth.AuthSession, error) {
			return nil, autherrors.ErrAuthFailed
		},
	}
	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {Name: "example.com", AuthAgent: agent},
		},
	}

	router := NewAuthRouter(provider, nil)
	router.WithRedisRateLimit(RateLimitConfig{
		MaxFailuresPerIPUser: 2,
		MaxFailuresPerIP:     100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}, nil)
	defer func() { _ = router.Close() }()

	ctx := WithClientIP(context.Background(), "10.0.0.1")
	for range 2 {
		_, _ = router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
	}
	_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
	if !errors.Is(err, autherrors.ErrRateLimited) {
		t.Fatalf("expected in-process limiting after nil-client fallback, got %v", err)
	}
}
