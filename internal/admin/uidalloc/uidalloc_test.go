package uidalloc

import (
	"sync"
	"testing"
)

func TestAllocate_Sequential(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 5; i++ {
		uid, err := Allocate(dir)
		if err != nil {
			t.Fatalf("Allocate() error at i=%d: %v", i, err)
		}
		expected := firstUID + uint32(i)
		if uid != expected {
			t.Errorf("Allocate() = %d, want %d", uid, expected)
		}
	}
}

func TestAllocate_Concurrent(t *testing.T) {
	dir := t.TempDir()

	const goroutines = 10
	const allocsEach = 100
	total := goroutines * allocsEach

	results := make(chan uint32, total)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < allocsEach; j++ {
				uid, err := Allocate(dir)
				if err != nil {
					t.Errorf("Allocate() error: %v", err)
					return
				}
				results <- uid
			}
		}()
	}

	wg.Wait()
	close(results)

	seen := make(map[uint32]bool, total)
	for uid := range results {
		if uid < firstUID {
			t.Errorf("uid %d is below firstUID %d", uid, firstUID)
		}
		if seen[uid] {
			t.Errorf("duplicate uid %d", uid)
		}
		seen[uid] = true
	}

	if len(seen) != total {
		t.Errorf("expected %d unique uids, got %d", total, len(seen))
	}

	// Verify values are sequential starting from firstUID.
	for i := 0; i < total; i++ {
		expected := firstUID + uint32(i)
		if !seen[expected] {
			t.Errorf("missing uid %d in allocated set", expected)
		}
	}
}
