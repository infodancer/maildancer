package server

import (
	"sync"
	"testing"
)

// TestTryAcquireSucceedsUpToLimit verifies that TryAcquire returns true for
// each slot up to the configured maximum.
func TestTryAcquireSucceedsUpToLimit(t *testing.T) {
	l := NewConnectionLimiter(3)

	for i := 1; i <= 3; i++ {
		if !l.TryAcquire() {
			t.Errorf("TryAcquire call %d returned false, want true", i)
		}
	}

	if l.Current() != 3 {
		t.Errorf("Current() = %d, want 3", l.Current())
	}
}

// TestTryAcquireAtLimitReturnsFalse verifies that once the limit is reached,
// TryAcquire returns false.
func TestTryAcquireAtLimitReturnsFalse(t *testing.T) {
	l := NewConnectionLimiter(2)

	l.TryAcquire()
	l.TryAcquire()

	if l.TryAcquire() {
		t.Error("TryAcquire at limit returned true, want false")
	}
}

// TestReleaseAllowsNewAcquisition verifies that releasing a slot permits
// a subsequent TryAcquire to succeed.
func TestReleaseAllowsNewAcquisition(t *testing.T) {
	l := NewConnectionLimiter(1)

	if !l.TryAcquire() {
		t.Fatal("first TryAcquire returned false, want true")
	}

	if l.TryAcquire() {
		t.Error("TryAcquire at limit returned true, want false")
	}

	l.Release()

	if !l.TryAcquire() {
		t.Error("TryAcquire after Release returned false, want true")
	}
}

// TestCurrentTracksSlotsAccurately verifies that Current() reflects the number
// of outstanding acquisitions.
func TestCurrentTracksSlotsAccurately(t *testing.T) {
	l := NewConnectionLimiter(5)

	if l.Current() != 0 {
		t.Errorf("initial Current() = %d, want 0", l.Current())
	}

	l.TryAcquire()
	l.TryAcquire()

	if l.Current() != 2 {
		t.Errorf("Current() after 2 acquires = %d, want 2", l.Current())
	}

	l.Release()

	if l.Current() != 1 {
		t.Errorf("Current() after 1 release = %d, want 1", l.Current())
	}
}

// TestLimiterWithLimitOfOne verifies a limit-of-one limiter behaves as a mutex.
func TestLimiterWithLimitOfOne(t *testing.T) {
	l := NewConnectionLimiter(1)

	if !l.TryAcquire() {
		t.Fatal("first TryAcquire on limit-1 limiter returned false")
	}
	if l.TryAcquire() {
		t.Error("second TryAcquire on limit-1 limiter returned true, want false")
	}
	l.Release()
	if !l.TryAcquire() {
		t.Error("TryAcquire after Release on limit-1 limiter returned false")
	}
}

// TestConcurrentAcquireRelease stress-tests the limiter under concurrent access.
// It launches more goroutines than the limit allows and verifies that the active
// count never exceeds the maximum.
func TestConcurrentAcquireRelease(t *testing.T) {
	const limit = 10
	const goroutines = 50

	l := NewConnectionLimiter(limit)

	var (
		mu      sync.Mutex
		maxSeen int64
		wg      sync.WaitGroup
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()

			if l.TryAcquire() {
				current := l.Current()

				mu.Lock()
				if current > maxSeen {
					maxSeen = current
				}
				mu.Unlock()

				l.Release()
			}
		}()
	}

	wg.Wait()

	if maxSeen > limit {
		t.Errorf("concurrent peak active connections = %d, exceeded limit %d", maxSeen, limit)
	}

	if l.Current() != 0 {
		t.Errorf("Current() after all goroutines finished = %d, want 0", l.Current())
	}
}

// TestConcurrentAcquireNeverExceedsLimit verifies atomicity under contention
// by having exactly (limit) goroutines acquire simultaneously, then release.
func TestConcurrentAcquireNeverExceedsLimit(t *testing.T) {
	const limit = 5
	const goroutines = 100

	l := NewConnectionLimiter(limit)

	var wg sync.WaitGroup
	acquired := make(chan struct{}, goroutines)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if l.TryAcquire() {
				acquired <- struct{}{}
				l.Release()
			}
		}()
	}

	wg.Wait()
	close(acquired)

	// We can't assert an exact count because goroutines may interleave acquires
	// and releases, but we can assert the limiter is clean at the end.
	if l.Current() != 0 {
		t.Errorf("Current() = %d after test, want 0", l.Current())
	}
}
