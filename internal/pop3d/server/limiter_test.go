package server

import (
	"sync"
	"testing"
)

func TestConnectionLimiter_TryAcquire(t *testing.T) {
	t.Run("succeeds up to max", func(t *testing.T) {
		limiter := NewConnectionLimiter(3)

		// Should succeed 3 times
		for i := 0; i < 3; i++ {
			if !limiter.TryAcquire() {
				t.Errorf("TryAcquire %d should succeed", i+1)
			}
		}

		if limiter.Current() != 3 {
			t.Errorf("Current() = %d, want 3", limiter.Current())
		}
	})

	t.Run("fails at capacity", func(t *testing.T) {
		limiter := NewConnectionLimiter(2)

		// Fill to capacity
		limiter.TryAcquire()
		limiter.TryAcquire()

		// Should fail
		if limiter.TryAcquire() {
			t.Error("TryAcquire should fail at capacity")
		}
	})

	t.Run("release allows new acquisitions", func(t *testing.T) {
		limiter := NewConnectionLimiter(1)

		// Acquire
		if !limiter.TryAcquire() {
			t.Fatal("first TryAcquire should succeed")
		}

		// At capacity
		if limiter.TryAcquire() {
			t.Fatal("second TryAcquire should fail")
		}

		// Release
		limiter.Release()

		// Should succeed again
		if !limiter.TryAcquire() {
			t.Error("TryAcquire after Release should succeed")
		}
	})
}

func TestConnectionLimiter_Current(t *testing.T) {
	limiter := NewConnectionLimiter(10)

	if limiter.Current() != 0 {
		t.Errorf("initial Current() = %d, want 0", limiter.Current())
	}

	limiter.TryAcquire()
	limiter.TryAcquire()

	if limiter.Current() != 2 {
		t.Errorf("Current() = %d, want 2", limiter.Current())
	}

	limiter.Release()

	if limiter.Current() != 1 {
		t.Errorf("Current() after Release = %d, want 1", limiter.Current())
	}
}

func TestConnectionLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewConnectionLimiter(100)
	var wg sync.WaitGroup

	// Launch 200 goroutines trying to acquire
	successCount := make(chan int, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.TryAcquire() {
				successCount <- 1
			}
		}()
	}

	wg.Wait()
	close(successCount)

	// Count successes
	count := 0
	for range successCount {
		count++
	}

	// Exactly 100 should succeed
	if count != 100 {
		t.Errorf("successful acquisitions = %d, want 100", count)
	}

	if limiter.Current() != 100 {
		t.Errorf("Current() = %d, want 100", limiter.Current())
	}
}

func TestConnectionLimiter_ConcurrentAcquireRelease(t *testing.T) {
	limiter := NewConnectionLimiter(10)
	var wg sync.WaitGroup

	// Run acquire/release cycles concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if limiter.TryAcquire() {
					limiter.Release()
				}
			}
		}()
	}

	wg.Wait()

	// After all goroutines complete, count should be 0
	if limiter.Current() != 0 {
		t.Errorf("Current() after all releases = %d, want 0", limiter.Current())
	}
}
