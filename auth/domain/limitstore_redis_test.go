package domain

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedisStore returns a redisLimitStore against an in-process miniredis,
// plus the server so tests can drive its clock. miniredis honours TTLs only
// when time is advanced explicitly with FastForward, which is what makes the
// expiry assertions below deterministic.
func newTestRedisStore(t *testing.T) (*redisLimitStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
		// Retries and the default dial timeout only serve to make the
		// dead-server test slow; the store's job is to report the error, not
		// to survive the outage.
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })
	return newRedisLimitStore(client), mr
}

func TestRedisLimitStore_IncrSetsTTLOnCreate(t *testing.T) {
	s, mr := newTestRedisStore(t)
	ctx := context.Background()

	n, err := s.incr(ctx, "auth:fail:ip:10.0.0.1", time.Minute)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if n != 1 {
		t.Fatalf("first incr = %d, want 1", n)
	}

	// The TTL must land on creation, or a counter never expires and an IP is
	// locked out on failures from an arbitrarily distant past.
	if ttl := mr.TTL("auth:fail:ip:10.0.0.1"); ttl != time.Minute {
		t.Errorf("TTL after create = %v, want 1m", ttl)
	}

	n, err = s.incr(ctx, "auth:fail:ip:10.0.0.1", time.Minute)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if n != 2 {
		t.Errorf("second incr = %d, want 2", n)
	}
}

// TestRedisLimitStore_IncrDoesNotExtendTTL is the important one: EXPIRE is
// conditional on the counter being new. If every increment reset the TTL, a
// steady trickle of failures would hold the window open forever and the
// counter would never age out.
func TestRedisLimitStore_IncrDoesNotExtendTTL(t *testing.T) {
	s, mr := newTestRedisStore(t)
	ctx := context.Background()
	key := "auth:fail:ip:10.0.0.1"

	if _, err := s.incr(ctx, key, time.Minute); err != nil {
		t.Fatalf("incr: %v", err)
	}
	mr.FastForward(30 * time.Second)
	if _, err := s.incr(ctx, key, time.Minute); err != nil {
		t.Fatalf("incr: %v", err)
	}

	if ttl := mr.TTL(key); ttl != 30*time.Second {
		t.Errorf("TTL after a second incr = %v, want 30s (unextended)", ttl)
	}

	mr.FastForward(31 * time.Second)
	n, err := s.incr(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if n != 1 {
		t.Errorf("incr after expiry = %d, want 1 (fresh window)", n)
	}
}

func TestRedisLimitStore_ExistsAndSet(t *testing.T) {
	s, mr := newTestRedisStore(t)
	ctx := context.Background()
	key := "auth:lock:ip:10.0.0.1"

	ok, err := s.exists(ctx, key)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if ok {
		t.Fatal("absent key reported present")
	}

	if err := s.set(ctx, key, time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	ok, err = s.exists(ctx, key)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !ok {
		t.Fatal("key set with a live TTL reported absent")
	}

	mr.FastForward(61 * time.Second)
	ok, err = s.exists(ctx, key)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if ok {
		t.Error("expired lockout reported present; lockouts must release on their own")
	}
}

func TestRedisLimitStore_Del(t *testing.T) {
	s, _ := newTestRedisStore(t)
	ctx := context.Background()

	if err := s.set(ctx, "a", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Absent keys mixed with present ones must not error -- recordSuccess
	// deletes both the counter and the lockout, and the lockout usually
	// does not exist.
	if err := s.del(ctx, "a", "never-existed"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if ok, _ := s.exists(ctx, "a"); ok {
		t.Error("key survived del")
	}

	// An empty key list is a no-op, not a Redis syntax error.
	if err := s.del(ctx); err != nil {
		t.Errorf("del with no keys: %v", err)
	}
}

// TestRedisLimitStore_ErrorsSurface confirms the store reports failures rather
// than swallowing them, since the fail-open decision belongs to the limiter --
// which logs it -- not to the store, which would hide it.
func TestRedisLimitStore_ErrorsSurface(t *testing.T) {
	s, mr := newTestRedisStore(t)
	ctx := context.Background()
	mr.Close() // server gone: every command should now fail

	if _, err := s.incr(ctx, "k", time.Minute); err == nil {
		t.Error("incr against a dead server returned no error")
	}
	if _, err := s.exists(ctx, "k"); err == nil {
		t.Error("exists against a dead server returned no error")
	}
	if err := s.set(ctx, "k", time.Minute); err == nil {
		t.Error("set against a dead server returned no error")
	}
	if err := s.del(ctx, "k"); err == nil {
		t.Error("del against a dead server returned no error")
	}
}

// TestRedisLimitStore_LimiterEndToEnd exercises the limiter over real Redis,
// including the cross-process case the whole change exists for: two limiters
// with independent state objects, sharing one Redis, must see each other's
// failures. This is what a per-process map could not do.
func TestRedisLimitStore_LimiterEndToEnd(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := RateLimitConfig{
		MaxFailuresPerIPUser: 3,
		MaxFailuresPerIP:     100,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}

	newLimiter := func() *authRateLimiter {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return newAuthRateLimiter(cfg, newRedisLimitStore(client))
	}

	imapd := newLimiter()
	pop3d := newLimiter()
	ctx := context.Background()
	ip := "10.0.0.1"
	user := "alice@example.com"

	// Two failures against imapd, one against pop3d: three in total, so the
	// threshold trips even though neither daemon saw three on its own.
	imapd.recordFailure(ctx, ip, user)
	imapd.recordFailure(ctx, ip, user)
	if imapd.isLimited(ctx, ip, user) {
		t.Fatal("locked out after 2 failures")
	}
	pop3d.recordFailure(ctx, ip, user)

	if !pop3d.isLimited(ctx, ip, user) {
		t.Error("pop3d does not see the shared lockout")
	}
	if !imapd.isLimited(ctx, ip, user) {
		t.Error("imapd does not see the lockout earned partly on pop3d")
	}

	// A success clears the pair for both.
	imapd.recordSuccess(ctx, ip, user)
	if pop3d.isLimited(ctx, ip, user) {
		t.Error("pop3d still locked out after imapd recorded a success")
	}

	// Lockout releases on its own once the TTL passes.
	for range 3 {
		imapd.recordFailure(ctx, ip, user)
	}
	if !imapd.isLimited(ctx, ip, user) {
		t.Fatal("expected lockout after 3 more failures")
	}
	mr.FastForward(16 * time.Minute)
	if imapd.isLimited(ctx, ip, user) {
		t.Error("lockout outlived its TTL; nothing sweeps it any more")
	}
}
