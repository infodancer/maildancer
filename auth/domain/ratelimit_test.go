package domain

import (
	"context"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

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
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100, // high so we only trigger per-pair
		MaxFailuresPerUser:   100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	ip := "10.0.0.1"
	user := "alice@example.com"

	// 2 failures -- not yet limited.
	rl.recordFailure(ip, user)
	rl.recordFailure(ip, user)
	if rl.isLimited(ip, user) {
		t.Fatal("should not be limited after 2 failures")
	}

	// 3rd failure triggers lockout.
	rl.recordFailure(ip, user)
	if !rl.isLimited(ip, user) {
		t.Fatal("should be limited after 3 failures")
	}

	// Different IP, same user -- not limited (per-user threshold is 100).
	if rl.isLimited("10.0.0.2", user) {
		t.Fatal("different IP should not be limited by per-pair limit")
	}

	// Same IP, different user -- not limited.
	if rl.isLimited(ip, "bob@example.com") {
		t.Fatal("different user should not be limited by per-pair limit")
	}

	// After lockout expires, no longer limited.
	now = now.Add(16 * time.Minute)
	if rl.isLimited(ip, user) {
		t.Fatal("should not be limited after lockout expires")
	}
}

func TestRateLimiter_PerIPLimit(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 100,
		MaxFailuresPerIP:     3,
		MaxFailuresPerUser:   100,
		Window:               5 * time.Minute,
		Lockout:              10 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	ip := "10.0.0.1"

	// Failures across different usernames still count toward per-IP.
	rl.recordFailure(ip, "alice@example.com")
	rl.recordFailure(ip, "bob@example.com")
	rl.recordFailure(ip, "carol@example.com")

	// Any username from this IP should be limited.
	if !rl.isLimited(ip, "dave@example.com") {
		t.Fatal("should be per-IP limited after 3 failures from different users")
	}

	// Different IP is fine.
	if rl.isLimited("10.0.0.2", "dave@example.com") {
		t.Fatal("different IP should not be limited")
	}
}

func TestRateLimiter_PerUserLimit(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 100,
		MaxFailuresPerIP:     100,
		MaxFailuresPerUser:   3,
		Window:               5 * time.Minute,
		Lockout:              10 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	user := "alice@example.com"

	// Failures from different IPs count toward per-user.
	rl.recordFailure("10.0.0.1", user)
	rl.recordFailure("10.0.0.2", user)
	rl.recordFailure("10.0.0.3", user)

	// Any IP trying this user should be limited.
	if !rl.isLimited("10.0.0.99", user) {
		t.Fatal("should be per-user limited after 3 failures from different IPs")
	}

	// Different user from same IPs is fine.
	if rl.isLimited("10.0.0.1", "bob@example.com") {
		t.Fatal("different user should not be limited by per-user limit")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		MaxFailuresPerUser:   100,
		Window:               5 * time.Minute,
		Lockout:              1 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	ip := "10.0.0.1"
	user := "alice@example.com"

	// 2 failures.
	rl.recordFailure(ip, user)
	rl.recordFailure(ip, user)

	// Advance past window -- old failures expire.
	now = now.Add(6 * time.Minute)

	// 1 more failure -- only 1 in the current window, under threshold.
	rl.recordFailure(ip, user)
	if rl.isLimited(ip, user) {
		t.Fatal("should not be limited; old failures expired from window")
	}
}

func TestRateLimiter_SuccessResetsIPUserPair(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		MaxFailuresPerUser:   100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	ip := "10.0.0.1"
	user := "alice@example.com"

	rl.recordFailure(ip, user)
	rl.recordFailure(ip, user)
	// 2 failures, then success.
	rl.recordSuccess(ip, user)

	// 2 more failures -- should not be limited (counter was reset).
	rl.recordFailure(ip, user)
	rl.recordFailure(ip, user)
	if rl.isLimited(ip, user) {
		t.Fatal("should not be limited; success should have reset pair counter")
	}
}

func TestRateLimiter_NoIPContext(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 100,
		MaxFailuresPerIP:     100,
		MaxFailuresPerUser:   3,
		Window:               5 * time.Minute,
		Lockout:              10 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	// No IP -- should still rate-limit by username.
	rl.recordFailure("", "alice@example.com")
	rl.recordFailure("", "alice@example.com")
	rl.recordFailure("", "alice@example.com")

	if !rl.isLimited("", "alice@example.com") {
		t.Fatal("should be limited by per-user even without IP")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     3,
		MaxFailuresPerUser:   3,
		Window:               5 * time.Minute,
		Lockout:              1 * time.Minute,
	}
	rl := newAuthRateLimiter(cfg)
	now := time.Now()
	rl.now = func() time.Time { return now }

	rl.recordFailure("10.0.0.1", "alice@example.com")

	// Advance past window + lockout.
	now = now.Add(10 * time.Minute)
	rl.cleanup()

	rl.mu.Lock()
	ipUserLen := len(rl.ipUser)
	ipLen := len(rl.ip)
	userLen := len(rl.user)
	rl.mu.Unlock()

	if ipUserLen != 0 || ipLen != 0 || userLen != 0 {
		t.Errorf("expected all maps empty after cleanup, got ipUser=%d ip=%d user=%d",
			ipUserLen, ipLen, userLen)
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
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		MaxFailuresPerUser:   100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}
	router.WithRateLimit(cfg)
	defer func() { _ = router.Close() }()

	ctx := WithClientIP(context.Background(), "10.0.0.1")

	// 3 failed attempts.
	for i := 0; i < 3; i++ {
		_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
		if err == nil {
			t.Fatal("expected auth failure")
		}
		if err == autherrors.ErrRateLimited {
			t.Fatalf("should not be rate limited on attempt %d", i+1)
		}
	}

	// 4th attempt -- should be rate limited, even with correct password.
	_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "correct")
	if err != autherrors.ErrRateLimited {
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
	for i := 0; i < 100; i++ {
		_, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
		if err == autherrors.ErrRateLimited {
			t.Fatalf("rate limited on attempt %d without WithRateLimit", i+1)
		}
	}
}
