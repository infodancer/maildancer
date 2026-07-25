package connfork

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGate is a scripted PeerGate.
type fakeGate struct {
	mu      sync.Mutex
	verdict Verdict
	err     error
	calls   int
	// block, when non-nil, holds each call until it is closed.
	block chan struct{}
}

func (g *fakeGate) CheckPeer(ctx context.Context, _ string) (Verdict, error) {
	g.mu.Lock()
	g.calls++
	block := g.block
	verdict, err := g.verdict, g.err
	g.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	return verdict, err
}

func (g *fakeGate) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// gateHarness runs a dispatcher whose "handler" is a stub binary that exits
// immediately, so tests can observe gate and tarpit behavior without a real
// protocol handler.
type gateHarness struct {
	srv      *Server
	addr     string
	started  atomic.Int64
	ended    atomic.Int64
	verdicts sync.Map // verdict string -> *atomic.Int64
	tarpit   atomic.Int64
	rejected atomic.Int64
	cancel   context.CancelFunc
	done     chan struct{}
}

func (h *gateHarness) verdictCount(v string) int64 {
	if c, ok := h.verdicts.Load(v); ok {
		return c.(*atomic.Int64).Load()
	}
	return 0
}

// newGateHarness starts a dispatcher on a loopback port. cfgFn may adjust the
// Config before the server is built.
func newGateHarness(t *testing.T, cfgFn func(*Config)) *gateHarness {
	t.Helper()

	// A port is needed up front; take one, close it, and let the dispatcher
	// bind it. A collision would fail loudly rather than silently pass.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}

	h := &gateHarness{addr: addr, done: make(chan struct{})}

	cfg := Config{
		Listeners: []Listener{{Address: addr, Mode: "test"}},
		// /bin/true exits immediately: enough to prove a handler was spawned.
		ExecPath:      "/bin/true",
		OnConnStart:   func() { h.started.Add(1) },
		OnConnEnd:     func() { h.ended.Add(1) },
		OnGateVerdict: func(v string) { h.bump(v) },
		OnTarpitStart: func() { h.tarpit.Add(1) },
		OnTarpitEnd:   func() { h.tarpit.Add(-1) },
		OnTarpitRejected: func() {
			h.rejected.Add(1)
		},
	}
	if cfgFn != nil {
		cfgFn(&cfg)
	}

	h.srv = NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		_ = h.srv.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("dispatcher did not shut down within 10s")
		}
	})

	waitForListener(t, addr)
	return h
}

func (h *gateHarness) bump(v string) {
	c, _ := h.verdicts.LoadOrStore(v, &atomic.Int64{})
	c.(*atomic.Int64).Add(1)
}

// waitForListener blocks until addr accepts connections.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s never came up", addr)
}

// eventually polls until fn is true or the timeout expires.
func eventually(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestGate_NilGateSpawnsHandler is the backward-compatibility guard: with no
// gate configured the dispatcher behaves exactly as before.
func TestGate_NilGateSpawnsHandler(t *testing.T) {
	h := newGateHarness(t, nil)

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "handler spawn", func() bool {
		return h.started.Load() >= 1
	})
	if got := h.verdictCount("allow") + h.verdictCount("deny") + h.verdictCount("error"); got != 0 {
		t.Errorf("gate consulted %d times with no gate configured", got)
	}
}

func TestGate_AllowedPeerReachesHandler(t *testing.T) {
	gate := &fakeGate{}
	h := newGateHarness(t, func(c *Config) { c.Gate = gate })

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "handler spawn", func() bool {
		return h.started.Load() >= 1
	})
	eventually(t, 5*time.Second, "allow verdict", func() bool {
		return h.verdictCount("allow") >= 1
	})
}

// TestGate_DeniedPeerNeverReachesHandler is the point of the whole gate: no
// subprocess, no handshake, no password hash for a banned peer.
func TestGate_DeniedPeerNeverReachesHandler(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{Banned: true, Reason: "banned"}}
	h := newGateHarness(t, func(c *Config) { c.Gate = gate })

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "deny verdict", func() bool {
		return h.verdictCount("deny") >= 1
	})
	// Give a handler every chance to appear, then assert it did not.
	time.Sleep(200 * time.Millisecond)
	if got := h.started.Load(); got != 0 {
		t.Errorf("%d handler(s) spawned for a denied peer", got)
	}
}

// TestGate_DeniedConnectionIsClosedSilently pins the scanner-facing behavior:
// no banner, no error, just a hold and a close. Anything written back would
// confirm a live service.
func TestGate_DeniedConnectionIsClosedSilently(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{
		Banned: true,
		Tarpit: 150 * time.Millisecond,
		Reason: "banned",
	}}
	h := newGateHarness(t, func(c *Config) { c.Gate = gate })

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	held := time.Since(start)

	if n != 0 {
		t.Errorf("server sent %d bytes to a denied peer: %q", n, buf[:n])
	}
	if !errors.Is(err, io.EOF) && err != nil {
		// A reset instead of a clean EOF is acceptable; anything read is not.
		t.Logf("read ended with %v (acceptable)", err)
	}
	if held < 100*time.Millisecond {
		t.Errorf("connection held for %v, want at least ~150ms of tarpit", held)
	}
}

// TestGate_TarpitDoesNotStarveHandlers is the self-DoS regression test. Fill
// the tarpit budget with denied connections, then confirm an allowed
// connection still gets a handler slot promptly. If tarpitted connections held
// MaxConns tokens, this would hang.
func TestGate_TarpitDoesNotStarveHandlers(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{
		Banned: true,
		Tarpit: 30 * time.Second, // long enough that nothing expires mid-test
		Reason: "banned",
	}}
	const maxConns = 4
	h := newGateHarness(t, func(c *Config) {
		c.Gate = gate
		c.MaxConns = maxConns
		c.MaxTarpit = 16
	})

	// Occupy far more connections than the handler budget.
	held := make([]net.Conn, 0, 12)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for range 12 {
		conn, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		held = append(held, conn)
	}

	eventually(t, 10*time.Second, "tarpit to fill", func() bool {
		return h.tarpit.Load() >= 8
	})
	if got := h.started.Load(); got != 0 {
		t.Fatalf("%d handler(s) spawned for denied peers", got)
	}

	// Now let a connection through and require a handler promptly. The gate is
	// shared, so flip it to allow.
	gate.mu.Lock()
	gate.verdict = Verdict{}
	gate.mu.Unlock()

	good, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial allowed: %v", err)
	}
	defer func() { _ = good.Close() }()

	eventually(t, 5*time.Second, "handler for the allowed peer", func() bool {
		return h.started.Load() >= 1
	})
}

// TestGate_TarpitBudgetRejectsOverflow covers the other half of the budget: at
// the cap, denied connections close immediately instead of queueing, and the
// overflow is counted so an undersized MaxTarpit is visible.
func TestGate_TarpitBudgetRejectsOverflow(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{
		Banned: true,
		Tarpit: 30 * time.Second,
		Reason: "banned",
	}}
	h := newGateHarness(t, func(c *Config) {
		c.Gate = gate
		c.MaxTarpit = 2
	})

	held := make([]net.Conn, 0, 8)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for range 8 {
		conn, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		held = append(held, conn)
	}

	eventually(t, 10*time.Second, "tarpit overflow", func() bool {
		return h.rejected.Load() >= 1
	})
	if got := h.tarpit.Load(); got > 2 {
		t.Errorf("tarpit holds %d connections, cap is 2", got)
	}
}

// TestGate_NegativeMaxTarpitClosesImmediately covers the operator who wants
// bans enforced without holding any sockets.
func TestGate_NegativeMaxTarpitClosesImmediately(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{
		Banned: true,
		Tarpit: 30 * time.Second,
		Reason: "banned",
	}}
	h := newGateHarness(t, func(c *Config) {
		c.Gate = gate
		c.MaxTarpit = -1
	})

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected the connection to be closed, got a successful read")
	}
	if got := h.tarpit.Load(); got != 0 {
		t.Errorf("tarpit gauge = %d with tarpitting disabled", got)
	}
}

// TestGate_ErrorFailsOpen pins the default: a broken gate must not become a
// total outage.
func TestGate_ErrorFailsOpen(t *testing.T) {
	gate := &fakeGate{err: errors.New("gate unavailable")}
	h := newGateHarness(t, func(c *Config) { c.Gate = gate })

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "handler spawn despite gate error", func() bool {
		return h.started.Load() >= 1
	})
	eventually(t, 5*time.Second, "error verdict", func() bool {
		return h.verdictCount("error") >= 1
	})
}

// TestGate_ErrorFailsClosedWhenStrict covers the opposite choice for a
// deployment that would rather be down than unprotected.
func TestGate_ErrorFailsClosedWhenStrict(t *testing.T) {
	gate := &fakeGate{err: errors.New("gate unavailable")}
	h := newGateHarness(t, func(c *Config) {
		c.Gate = gate
		c.StrictGate = true
	})

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "error verdict", func() bool {
		return h.verdictCount("error") >= 1
	})
	time.Sleep(200 * time.Millisecond)
	if got := h.started.Load(); got != 0 {
		t.Errorf("%d handler(s) spawned with strict_gate and a failing gate", got)
	}
}

// TestGate_TimeoutIsAGateError makes sure a hung gate cannot hold a connection
// (and its handler token) indefinitely.
func TestGate_TimeoutIsAGateError(t *testing.T) {
	gate := &fakeGate{block: make(chan struct{})}
	defer close(gate.block)

	h := newGateHarness(t, func(c *Config) {
		c.Gate = gate
		c.GateTimeout = 100 * time.Millisecond
	})

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "gate timeout recorded as an error", func() bool {
		return h.verdictCount("error") >= 1
	})
	// Fail-open is the default, so the connection is served anyway.
	eventually(t, 5*time.Second, "handler spawn after gate timeout", func() bool {
		return h.started.Load() >= 1
	})
}

// TestGate_ShutdownReleasesTarpittedConnections keeps a long tarpit from
// blocking process shutdown.
func TestGate_ShutdownReleasesTarpittedConnections(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{
		Banned: true,
		Tarpit: 10 * time.Minute, // far longer than any test should wait
		Reason: "banned",
	}}
	h := newGateHarness(t, func(c *Config) { c.Gate = gate })

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventually(t, 5*time.Second, "tarpit to engage", func() bool {
		return h.tarpit.Load() >= 1
	})

	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("dispatcher blocked on a tarpitted connection during shutdown")
	}
}

// TestGate_EmptyClientIPSkipsGate documents that an unusable address is not
// worth an RPC: there is nothing to match against a ban list.
func TestGate_EmptyClientIPSkipsGate(t *testing.T) {
	gate := &fakeGate{verdict: Verdict{Banned: true}}
	srv := NewServer(Config{Gate: gate})

	if _, denied := srv.gateVerdict(context.Background(), ""); denied {
		t.Error("empty client IP was denied")
	}
	if got := gate.callCount(); got != 0 {
		t.Errorf("gate called %d times for an empty client IP", got)
	}
}
