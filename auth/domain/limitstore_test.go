package domain

import (
	"context"
	"testing"
	"time"
)

// newClockedMemStore returns a memLimitStore with a controllable clock and a
// function to advance it.
func newClockedMemStore() (*memLimitStore, func(time.Duration)) {
	s := newMemLimitStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	return s, func(d time.Duration) { now = now.Add(d) }
}

func TestMemLimitStore_IncrCountsWithinTTL(t *testing.T) {
	s, _ := newClockedMemStore()
	ctx := context.Background()

	for want := int64(1); want <= 3; want++ {
		got, err := s.incr(ctx, "k", time.Minute)
		if err != nil {
			t.Fatalf("incr: %v", err)
		}
		if got != want {
			t.Fatalf("incr = %d, want %d", got, want)
		}
	}
}

// TestMemLimitStore_IncrRestartsAfterTTL pins the fixed-window behavior that
// replaced the old sliding window of timestamps: once the key expires the
// count starts over, rather than individual failures aging out one at a time.
func TestMemLimitStore_IncrRestartsAfterTTL(t *testing.T) {
	s, advance := newClockedMemStore()
	ctx := context.Background()

	if _, err := s.incr(ctx, "k", time.Minute); err != nil {
		t.Fatalf("incr: %v", err)
	}
	if _, err := s.incr(ctx, "k", time.Minute); err != nil {
		t.Fatalf("incr: %v", err)
	}

	advance(2 * time.Minute)

	got, err := s.incr(ctx, "k", time.Minute)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if got != 1 {
		t.Errorf("incr after TTL = %d, want 1 (fresh window)", got)
	}
}

func TestMemLimitStore_ExistsRespectsTTL(t *testing.T) {
	s, advance := newClockedMemStore()
	ctx := context.Background()

	if ok, _ := s.exists(ctx, "k"); ok {
		t.Fatal("absent key reported present")
	}
	if err := s.set(ctx, "k", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	if ok, _ := s.exists(ctx, "k"); !ok {
		t.Fatal("key set with a live TTL reported absent")
	}

	advance(61 * time.Second)
	if ok, _ := s.exists(ctx, "k"); ok {
		t.Fatal("expired key reported present")
	}
}

// TestMemLimitStore_SetOverwritesTTL matters for lockouts: a repeat offender's
// marker must be extended by a fresh write, not left on the original deadline.
func TestMemLimitStore_SetOverwritesTTL(t *testing.T) {
	s, advance := newClockedMemStore()
	ctx := context.Background()

	if err := s.set(ctx, "k", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	advance(30 * time.Second)
	if err := s.set(ctx, "k", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	advance(45 * time.Second)

	if ok, _ := s.exists(ctx, "k"); !ok {
		t.Error("re-set key expired on the original deadline; TTL was not extended")
	}
}

func TestMemLimitStore_Del(t *testing.T) {
	s, _ := newClockedMemStore()
	ctx := context.Background()

	if err := s.set(ctx, "a", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s.set(ctx, "b", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Deleting an absent key alongside present ones is not an error.
	if err := s.del(ctx, "a", "b", "missing"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if ok, _ := s.exists(ctx, "a"); ok {
		t.Error("key a survived del")
	}
	if ok, _ := s.exists(ctx, "b"); ok {
		t.Error("key b survived del")
	}
}

// TestMemLimitStore_PrunesUntouchedKeys is the memory-growth guard. Expiry on
// access alone would leak entries for keys nobody revisits, which is exactly
// what a spray from many source addresses produces: one key each, touched
// once. Writes must sweep, since there is no cleanup goroutine any more.
func TestMemLimitStore_PrunesUntouchedKeys(t *testing.T) {
	s, advance := newClockedMemStore()
	ctx := context.Background()

	for i := range 100 {
		key := "sprayer-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		if _, err := s.incr(ctx, key, time.Minute); err != nil {
			t.Fatalf("incr: %v", err)
		}
	}
	if n := s.size(); n == 0 {
		t.Fatal("expected entries after 100 distinct keys")
	}

	advance(2 * time.Minute)

	// A single unrelated write must reclaim every expired entry.
	if _, err := s.incr(ctx, "fresh", time.Minute); err != nil {
		t.Fatalf("incr: %v", err)
	}
	if n := s.size(); n != 1 {
		t.Errorf("size after expiry = %d, want 1 (only the fresh key)", n)
	}
}
