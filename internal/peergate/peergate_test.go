package peergate

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/connfork"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// fakeSessionService serves CheckPeer from a scripted ban set.
type fakeSessionService struct {
	smpb.UnimplementedSessionServiceServer

	mu     sync.Mutex
	banned map[string]bool
	err    error
	calls  int
}

func (s *fakeSessionService) CheckPeer(_ context.Context, req *smpb.CheckPeerRequest) (*smpb.CheckPeerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.banned[req.Ip] {
		return &smpb.CheckPeerResponse{
			Banned:   true,
			TarpitMs: 30_000,
			Reason:   "banned",
		}, nil
	}
	return &smpb.CheckPeerResponse{}, nil
}

func (s *fakeSessionService) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *fakeSessionService) setBanned(ip string, banned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.banned == nil {
		s.banned = make(map[string]bool)
	}
	s.banned[ip] = banned
}

func (s *fakeSessionService) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// newTestGate wires a Gate to an in-process gRPC server over bufconn.
func newTestGate(t *testing.T, cfgFn func(*Config)) (*Gate, *fakeSessionService, *atomic.Int64) {
	t.Helper()

	svc := &fakeSessionService{banned: make(map[string]bool)}
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(gsrv, svc)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var cacheHits atomic.Int64
	cfg := Config{}
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	gate, err := New(cfg, conn, Metrics{
		OnCache: func(hit bool) {
			if hit {
				cacheHits.Add(1)
			}
		},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gate, svc, &cacheHits
}

func TestCheckPeer_AllowsUnbannedPeer(t *testing.T) {
	gate, _, _ := newTestGate(t, nil)

	verdict, err := gate.CheckPeer(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if verdict.Banned {
		t.Error("unbanned peer denied")
	}
}

func TestCheckPeer_DeniesBannedPeer(t *testing.T) {
	gate, svc, _ := newTestGate(t, nil)
	svc.setBanned("203.0.113.5", true)

	verdict, err := gate.CheckPeer(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if !verdict.Banned {
		t.Fatal("banned peer allowed")
	}
	if verdict.Tarpit != 30*time.Second {
		t.Errorf("tarpit = %v, want 30s (from the server's tarpit_ms)", verdict.Tarpit)
	}
	if verdict.Reason != "banned" {
		t.Errorf("reason = %q", verdict.Reason)
	}
}

// TestCheckPeer_AllowlistCostsNoRPC pins both halves of the allowlist promise:
// it wins over an active ban, and it does not spend a round trip.
func TestCheckPeer_AllowlistCostsNoRPC(t *testing.T) {
	gate, svc, _ := newTestGate(t, func(c *Config) {
		c.Allowlist = []string{"10.0.0.0/8", "::1/128"}
	})
	svc.setBanned("10.1.2.3", true)

	for _, ip := range []string{"10.1.2.3", "::1"} {
		verdict, err := gate.CheckPeer(context.Background(), ip)
		if err != nil {
			t.Fatalf("CheckPeer(%s): %v", ip, err)
		}
		if verdict.Banned {
			t.Errorf("allowlisted %s was denied", ip)
		}
	}
	if got := svc.callCount(); got != 0 {
		t.Errorf("gate made %d RPCs for allowlisted peers, want 0", got)
	}
}

func TestNew_InvalidAllowlistIsAnError(t *testing.T) {
	_, err := New(Config{Allowlist: []string{"not-a-cidr"}}, &grpc.ClientConn{}, Metrics{}, nil)
	if err == nil {
		t.Error("invalid allowlist CIDR accepted")
	}
}

func TestNew_DisabledReturnsNilGate(t *testing.T) {
	disabled := false
	gate, err := New(Config{Enabled: &disabled}, &grpc.ClientConn{}, Metrics{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if gate.Enabled() {
		t.Error("disabled config produced an enabled gate")
	}
	// A nil gate must be safe to use and allow everything.
	verdict, err := gate.CheckPeer(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatalf("CheckPeer on nil gate: %v", err)
	}
	if verdict.Banned {
		t.Error("nil gate denied a peer")
	}
	gate.Forget("203.0.113.5") // must not panic
}

// TestConfig_EnabledByDefault is the secure-by-default assertion: absent
// configuration means the gate runs.
func TestConfig_EnabledByDefault(t *testing.T) {
	var cfg Config
	if !cfg.IsEnabled() {
		t.Error("gate is disabled with no configuration; it must default on")
	}

	enabled := true
	cfg.Enabled = &enabled
	if !cfg.IsEnabled() {
		t.Error("explicit true read as disabled")
	}

	disabled := false
	cfg.Enabled = &disabled
	if cfg.IsEnabled() {
		t.Error("explicit false read as enabled")
	}
}

// TestCheckPeer_CacheAbsorbsReconnectStorm is why the cache exists: a banned
// peer reconnecting repeatedly must not cost one RPC per connection.
func TestCheckPeer_CacheAbsorbsReconnectStorm(t *testing.T) {
	gate, svc, hits := newTestGate(t, nil)
	svc.setBanned("203.0.113.5", true)
	ctx := context.Background()

	for i := range 50 {
		verdict, err := gate.CheckPeer(ctx, "203.0.113.5")
		if err != nil {
			t.Fatalf("CheckPeer %d: %v", i, err)
		}
		if !verdict.Banned {
			t.Fatalf("CheckPeer %d: banned peer allowed", i)
		}
	}

	if got := svc.callCount(); got != 1 {
		t.Errorf("gate made %d RPCs for 50 connections, want 1", got)
	}
	if got := hits.Load(); got != 49 {
		t.Errorf("cache hits = %d, want 49", got)
	}
}

// TestCheckPeer_CacheTTLAsymmetry pins the deliberate difference: a stale allow
// is a missed ban for a short window, while a stale deny only over-punishes an
// address that just earned one -- so denies are cached for longer.
func TestCheckPeer_CacheTTLAsymmetry(t *testing.T) {
	gate, svc, _ := newTestGate(t, func(c *Config) {
		c.AllowTTL = 10 * time.Second
		c.DenyTTL = 60 * time.Second
	})

	now := time.Now()
	gate.cache.now = func() time.Time { return now }
	ctx := context.Background()

	// An allow, then a deny for a different address.
	if _, err := gate.CheckPeer(ctx, "198.51.100.1"); err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	svc.setBanned("203.0.113.5", true)
	if _, err := gate.CheckPeer(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if got := svc.callCount(); got != 2 {
		t.Fatalf("setup made %d RPCs, want 2", got)
	}

	// 15s later: the allow has expired, the deny has not.
	now = now.Add(15 * time.Second)

	if _, err := gate.CheckPeer(ctx, "198.51.100.1"); err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if got := svc.callCount(); got != 3 {
		t.Errorf("allow was not re-checked after AllowTTL (calls=%d, want 3)", got)
	}

	if _, err := gate.CheckPeer(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if got := svc.callCount(); got != 3 {
		t.Errorf("deny was re-checked before DenyTTL (calls=%d, want 3)", got)
	}

	// Past DenyTTL it is re-checked too.
	now = now.Add(60 * time.Second)
	if _, err := gate.CheckPeer(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if got := svc.callCount(); got != 4 {
		t.Errorf("deny was not re-checked after DenyTTL (calls=%d, want 4)", got)
	}
}

// TestCheckPeer_ErrorsAreNotCached keeps one outage from becoming a
// cache-TTL-long blind spot.
func TestCheckPeer_ErrorsAreNotCached(t *testing.T) {
	gate, svc, _ := newTestGate(t, nil)
	svc.setErr(errors.New("session-manager down"))
	ctx := context.Background()

	for i := range 3 {
		if _, err := gate.CheckPeer(ctx, "203.0.113.5"); err == nil {
			t.Fatalf("attempt %d: expected an error", i+1)
		}
	}
	if got := svc.callCount(); got != 3 {
		t.Errorf("gate made %d RPCs, want 3: errors must not be cached", got)
	}

	// Once the server recovers, the next check sees the real verdict.
	svc.setErr(nil)
	svc.setBanned("203.0.113.5", true)
	verdict, err := gate.CheckPeer(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("CheckPeer after recovery: %v", err)
	}
	if !verdict.Banned {
		t.Error("stale allow served after recovery")
	}
}

// TestForget lets an operator unban take effect without waiting out DenyTTL.
func TestForget(t *testing.T) {
	gate, svc, _ := newTestGate(t, nil)
	svc.setBanned("203.0.113.5", true)
	ctx := context.Background()

	if verdict, err := gate.CheckPeer(ctx, "203.0.113.5"); err != nil || !verdict.Banned {
		t.Fatalf("setup: verdict=%+v err=%v", verdict, err)
	}

	svc.setBanned("203.0.113.5", false)
	// Still cached as denied.
	if verdict, _ := gate.CheckPeer(ctx, "203.0.113.5"); !verdict.Banned {
		t.Fatal("cache did not hold the deny")
	}

	gate.Forget("203.0.113.5")
	if verdict, err := gate.CheckPeer(ctx, "203.0.113.5"); err != nil || verdict.Banned {
		t.Errorf("after Forget: verdict=%+v err=%v, want allowed", verdict, err)
	}
}

func TestConfig_Normalize(t *testing.T) {
	cfg := Config{
		GateTimeoutStr: "5s",
		AllowTTLStr:    "30s",
		DenyTTLStr:     "10m",
		MaxTarpit:      64,
		CacheSize:      100,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.GateTimeout != 5*time.Second || cfg.AllowTTL != 30*time.Second || cfg.DenyTTL != 10*time.Minute {
		t.Errorf("durations not parsed: %+v", cfg)
	}
	if cfg.MaxTarpit != 64 || cfg.CacheSize != 100 {
		t.Errorf("counts overwritten: %+v", cfg)
	}
}

func TestConfig_NormalizeFillsDefaults(t *testing.T) {
	var cfg Config
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.GateTimeout != DefaultGateTimeout || cfg.AllowTTL != DefaultAllowTTL ||
		cfg.DenyTTL != DefaultDenyTTL || cfg.MaxTarpit != DefaultMaxTarpit ||
		cfg.CacheSize != DefaultCacheSize {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

// TestConfig_NormalizeKeepsNegativeMaxTarpit preserves the "enforce bans but
// hold nothing" choice, which a zero-means-default rule would erase.
func TestConfig_NormalizeKeepsNegativeMaxTarpit(t *testing.T) {
	cfg := Config{MaxTarpit: -1}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.MaxTarpit != -1 {
		t.Errorf("MaxTarpit = %d, want -1 preserved", cfg.MaxTarpit)
	}
}

func TestConfig_NormalizeRejectsBadDuration(t *testing.T) {
	cfg := Config{GateTimeoutStr: "soon"}
	if err := cfg.Normalize(); err == nil {
		t.Error("invalid duration accepted")
	}
}

// TestVerdictCache_BoundedUnderSpray is the memory guard: a spray from many
// distinct addresses must not grow the cache without limit. Generational
// eviction bounds it at 2x the configured size.
func TestVerdictCache_BoundedUnderSpray(t *testing.T) {
	c := newVerdictCache(100)
	for i := range 10_000 {
		key := "10." + itoa(i/65536) + "." + itoa((i/256)%256) + "." + itoa(i%256)
		c.put(key, connfork.Verdict{}, time.Minute)
	}
	if got := c.size(); got > 200 {
		t.Errorf("cache holds %d entries for a size of 100; generational eviction is not bounding it", got)
	}
}

// TestVerdictCache_PreviousGenerationStillServes confirms the two-map lookup:
// an entry survives one generation roll, which is the guarantee generational
// eviction offers. Two rolls drop it -- that is eviction working, and it costs
// one extra RPC rather than a wrong answer, which is the trade a cache makes.
func TestVerdictCache_PreviousGenerationStillServes(t *testing.T) {
	c := newVerdictCache(4)
	c.put("first", connfork.Verdict{Banned: true}, time.Minute)

	// Cross the cap once, so "first" moves to the previous generation.
	for i := range 4 {
		c.put("filler-"+itoa(i), connfork.Verdict{}, time.Minute)
	}

	verdict, ok := c.get("first")
	if !ok {
		t.Fatal("entry lost after a single generation roll")
	}
	if !verdict.Banned {
		t.Error("verdict corrupted across generations")
	}

	// A second roll is allowed to drop it.
	for i := range 8 {
		c.put("more-"+itoa(i), connfork.Verdict{}, time.Minute)
	}
	if _, ok := c.get("first"); ok {
		t.Log("entry survived two rolls; harmless, but not guaranteed")
	}
}

func TestVerdictCache_ExpiredEntryIsAMiss(t *testing.T) {
	c := newVerdictCache(10)
	now := time.Now()
	c.now = func() time.Time { return now }

	c.put("k", connfork.Verdict{Banned: true}, time.Minute)
	if _, ok := c.get("k"); !ok {
		t.Fatal("live entry reported as a miss")
	}

	now = now.Add(61 * time.Second)
	if _, ok := c.get("k"); ok {
		t.Error("expired entry served")
	}
}

// itoa avoids importing strconv for three call sites in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
