package peergate

import (
	"sync"
	"time"
)

// connRateCounter counts accepts per key inside a fixed window and reports the
// first crossing of a threshold in each window.
//
// It lives here rather than in connfork for three reasons. CheckPeer is called
// once per accepted connection, so this sees every accept -- the 10s/60s verdict
// cache sits *inside* CheckPeer, between it and the RPC, so it hides accepts
// from session-manager but not from here. The allowlist is also here and only
// here, so a counter in the dispatcher would count and eventually report the
// operator's own networks. And connfork is deliberately policy-agnostic, while
// this package's job is already "how cheaply is the question answered".
//
// Eviction is generational, copied from verdictCache for the same reason: the
// threat is a spray from many distinct addresses, and LRU bookkeeping would be
// O(n) per insert exactly when the structure is full, which under a spray is
// always. verdictCache itself is not reused because it deletes on expiry and
// returns a miss, whereas this needs one read-modify-write under a single lock.
//
// A nil *connRateCounter is safe and never reports, which is how a negative
// threshold disables detection.
type connRateCounter struct {
	mu        sync.Mutex
	threshold int
	max       int
	window    time.Duration
	cur       map[string]*rateEntry
	prev      map[string]*rateEntry
	now       func() time.Time // injectable for tests
}

type rateEntry struct {
	count       int
	windowStart time.Time
	// reported is what makes a sustained flood cost one report per window
	// instead of one per accept past the threshold.
	reported bool
}

// newConnRateCounter returns nil when threshold is negative, matching the
// max_tarpit and revoke_after convention: 0 takes the default, negative
// disables.
func newConnRateCounter(threshold, max int, window time.Duration) *connRateCounter {
	if threshold < 0 {
		return nil
	}
	if threshold == 0 {
		threshold = DefaultConnRateThreshold
	}
	if max <= 0 {
		max = DefaultCacheSize
	}
	if window <= 0 {
		window = DefaultConnRateWindow
	}
	return &connRateCounter{
		threshold: threshold,
		max:       max,
		window:    window,
		cur:       make(map[string]*rateEntry),
		now:       time.Now,
	}
}

// observe records one accept for key and reports whether it is the first
// crossing of the threshold in the current window.
func (c *connRateCounter) observe(key string) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	entry := c.lookupLocked(key)
	if entry == nil {
		if len(c.cur) >= c.max {
			// Roll: the live generation becomes the previous one. This can drop
			// a partial count for an address in the old generation, which
			// under-reports rather than over-reports -- the safe direction for
			// something that will eventually ban.
			c.prev = c.cur
			c.cur = make(map[string]*rateEntry, c.max/4)
		}
		entry = &rateEntry{windowStart: now}
		c.cur[key] = entry
	}

	if now.Sub(entry.windowStart) >= c.window {
		entry.count = 0
		entry.windowStart = now
		entry.reported = false
	}

	entry.count++
	if entry.count < c.threshold || entry.reported {
		return false
	}
	entry.reported = true
	return true
}

// lookupLocked finds an entry in either generation, promoting a hit from the
// previous generation so an address that keeps connecting is not lost on the
// next roll.
func (c *connRateCounter) lookupLocked(key string) *rateEntry {
	if e, ok := c.cur[key]; ok {
		return e
	}
	if c.prev == nil {
		return nil
	}
	e, ok := c.prev[key]
	if !ok {
		return nil
	}
	if len(c.cur) < c.max {
		c.cur[key] = e
		delete(c.prev, key)
	}
	return e
}

// size reports entries across both generations. Test-only.
func (c *connRateCounter) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.cur)
	if c.prev != nil {
		n += len(c.prev)
	}
	return n
}
