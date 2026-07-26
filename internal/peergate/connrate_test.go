package peergate

import (
	"fmt"
	"testing"
	"time"
)

// newTestCounter builds a counter over a clock the test drives, so a window
// rollover is deterministic rather than a sleep.
func newTestCounter(t *testing.T, threshold, max int, window time.Duration) (*connRateCounter, func(time.Duration)) {
	t.Helper()

	now := time.Unix(1_700_000_000, 0)
	c := newConnRateCounter(threshold, max, window)
	c.now = func() time.Time { return now }
	return c, func(d time.Duration) { now = now.Add(d) }
}

// TestConnRateCounter_Observe is the core contract: crossing the threshold
// reports exactly once per window, however long the flood lasts. Reporting per
// connection would be one RPC per connection, which is the cost the whole gate
// exists to avoid.
func TestConnRateCounter_Observe(t *testing.T) {
	t.Run("under the threshold never crosses", func(t *testing.T) {
		c, _ := newTestCounter(t, 5, 128, time.Minute)
		for i := range 4 {
			if c.observe("peer") {
				t.Fatalf("crossed at accept %d, threshold is 5", i+1)
			}
		}
	})

	t.Run("crossing reports once", func(t *testing.T) {
		c, _ := newTestCounter(t, 5, 128, time.Minute)
		var crossings int
		for range 5 {
			if c.observe("peer") {
				crossings++
			}
		}
		if crossings != 1 {
			t.Errorf("got %d crossings, want 1", crossings)
		}
	})

	t.Run("a sustained flood still reports once per window", func(t *testing.T) {
		c, _ := newTestCounter(t, 5, 128, time.Minute)
		var crossings int
		for range 500 {
			if c.observe("peer") {
				crossings++
			}
		}
		if crossings != 1 {
			t.Errorf("got %d crossings across 500 accepts in one window, want 1", crossings)
		}
	})

	t.Run("the window rearms", func(t *testing.T) {
		c, advance := newTestCounter(t, 3, 128, time.Minute)
		for range 10 {
			c.observe("peer")
		}
		advance(61 * time.Second)

		var crossings int
		for range 3 {
			if c.observe("peer") {
				crossings++
			}
		}
		if crossings != 1 {
			t.Errorf("got %d crossings in the second window, want 1", crossings)
		}
	})

	t.Run("a partial window does not rearm", func(t *testing.T) {
		c, advance := newTestCounter(t, 3, 128, time.Minute)
		for range 3 {
			c.observe("peer")
		}
		advance(30 * time.Second)
		if c.observe("peer") {
			t.Error("reported twice inside one window")
		}
	})

	t.Run("distinct keys count independently", func(t *testing.T) {
		c, _ := newTestCounter(t, 3, 128, time.Minute)
		for range 2 {
			c.observe("a")
			c.observe("b")
		}
		if c.observe("a") == false {
			t.Error("key a did not cross on its own third accept")
		}
		if c.observe("b") == false {
			t.Error("key b did not cross on its own third accept")
		}
	})
}

// TestConnRateCounter_BoundedUnderSpray is the memory-safety property. The
// measured attack came from ~750 distinct addresses in a few hours, each
// connecting once, so an unbounded per-address map is a memory-exhaustion vector
// reachable by anyone who can open a socket.
func TestConnRateCounter_BoundedUnderSpray(t *testing.T) {
	const max = 64
	c, _ := newTestCounter(t, 5, max, time.Minute)

	for i := range max * 20 {
		c.observe(fmt.Sprintf("peer-%d", i))
	}

	// Two generations, each capped at max.
	if got := c.size(); got > 2*max {
		t.Errorf("counter holds %d entries after %d distinct addresses, want at most %d",
			got, max*20, 2*max)
	}
}

// TestConnRateCounter_DisabledByNegativeThreshold follows the convention
// max_tarpit and revoke_after already use: 0 means default, negative disables.
// A third convention here would be a trap.
func TestConnRateCounter_DisabledByNegativeThreshold(t *testing.T) {
	if c := newConnRateCounter(-1, 128, time.Minute); c != nil {
		t.Error("negative threshold built a counter; it must disable detection")
	}

	// And a nil counter is safe to use, matching the rest of this package.
	var c *connRateCounter
	if c.observe("peer") {
		t.Error("nil counter reported a crossing")
	}
	if c.size() != 0 {
		t.Error("nil counter reported entries")
	}
}
