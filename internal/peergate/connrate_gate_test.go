package peergate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/peersignal"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"net"
	"sync/atomic"
)

// reportingService records ReportPeer calls alongside the CheckPeer behaviour
// fakeSessionService already provides.
type reportingService struct {
	fakeSessionService

	rmu     sync.Mutex
	reports []*smpb.ReportPeerRequest
}

func (s *reportingService) ReportPeer(_ context.Context, req *smpb.ReportPeerRequest) (*smpb.ReportPeerResponse, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	s.reports = append(s.reports, req)
	return &smpb.ReportPeerResponse{}, nil
}

func (s *reportingService) reportCount() int {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	return len(s.reports)
}

func (s *reportingService) signalsFor(ip string) []string {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	var out []string
	for _, r := range s.reports {
		if r.Ip == ip {
			out = append(out, r.Signal)
		}
	}
	return out
}

// newReportingGate is newTestGate with a service that also records ReportPeer,
// plus the connection-rate metric callback.
func newReportingGate(t *testing.T, cfgFn func(*Config)) (*Gate, *reportingService, map[string]*atomic.Int64) {
	t.Helper()

	svc := &reportingService{fakeSessionService: fakeSessionService{banned: make(map[string]bool)}}
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

	counts := map[string]*atomic.Int64{
		"reported":          {},
		"suppressed_banned": {},
	}
	cfg := Config{}
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	gate, err := New(cfg, conn, Metrics{
		OnConnRate: func(result string) {
			if c, ok := counts[result]; ok {
				c.Add(1)
			}
		},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gate, svc, counts
}

// waitForReports blocks until the service has at least n reports, since the
// report is fired from a goroutine.
func waitForReports(t *testing.T, svc *reportingService, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if svc.reportCount() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d report(s) arrived within 3s, want %d", svc.reportCount(), n)
}

// TestCheckPeer_ConnRateCountsCacheHits is the regression guard for the entire
// premise of putting the counter here.
//
// The verdict cache means session-manager sees roughly one CheckPeer RPC per
// address per AllowTTL, so a counter derived from RPCs would undercount a flood
// by exactly the factor that matters. CheckPeer itself is called once per
// accepted connection, and the cache sits inside it -- so N connections behind
// one cached verdict must still cross the threshold.
func TestCheckPeer_ConnRateCountsCacheHits(t *testing.T) {
	gate, svc, counts := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = 5
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	for range 5 {
		if _, err := gate.CheckPeer(ctx, ip, true); err != nil {
			t.Fatalf("CheckPeer: %v", err)
		}
	}

	// One RPC for the verdict; the other four accepts were cache hits.
	if got := svc.callCount(); got != 1 {
		t.Fatalf("CheckPeer RPCs = %d, want 1: the cache is not absorbing them, "+
			"so this test is not exercising the case it exists for", got)
	}
	waitForReports(t, svc, 1)
	if got := svc.signalsFor(ip); len(got) != 1 || got[0] != peersignal.ConnectionRate {
		t.Errorf("signals = %v, want one %q", got, peersignal.ConnectionRate)
	}
	if got := counts["reported"].Load(); got != 1 {
		t.Errorf("reported metric = %d, want 1", got)
	}
}

// TestCheckPeer_ConnRateReportsOncePerWindow keeps a sustained flood to one RPC
// per window. Reporting per accept past the threshold would turn the signal into
// the load it is trying to describe.
func TestCheckPeer_ConnRateReportsOncePerWindow(t *testing.T) {
	gate, svc, _ := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = 3
		c.ConnRateWindowStr = "1h"
	})
	ctx := context.Background()

	for range 200 {
		if _, err := gate.CheckPeer(ctx, "203.0.113.5", true); err != nil {
			t.Fatalf("CheckPeer: %v", err)
		}
	}

	waitForReports(t, svc, 1)
	// Give any surplus report a chance to land before asserting there is none.
	time.Sleep(50 * time.Millisecond)
	if got := svc.reportCount(); got != 1 {
		t.Errorf("reports = %d across 200 accepts in one window, want 1", got)
	}
}

// TestCheckPeer_AllowlistedPeerIsNeverRateReported is why the counter belongs in
// this package. The allowlist lives here and only here, so a counter in the
// dispatcher could not have skipped the operator's own networks without
// duplicating it -- and hammering the management network is exactly what a
// monitoring check looks like.
func TestCheckPeer_AllowlistedPeerIsNeverRateReported(t *testing.T) {
	gate, svc, counts := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = 2
		c.Allowlist = []string{"10.0.0.0/8"}
	})
	ctx := context.Background()

	for range 50 {
		if _, err := gate.CheckPeer(ctx, "10.1.2.3", true); err != nil {
			t.Fatalf("CheckPeer: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if got := svc.reportCount(); got != 0 {
		t.Errorf("reports = %d for an allowlisted peer, want 0", got)
	}
	if got := svc.callCount(); got != 0 {
		t.Errorf("CheckPeer RPCs = %d for an allowlisted peer, want 0", got)
	}
	if got := counts["reported"].Load(); got != 0 {
		t.Errorf("reported metric = %d for an allowlisted peer, want 0", got)
	}
}

// TestCheckPeer_ConnRateIsScopedByListenerRole mirrors the cache scoping. A
// submission storm and an inbound-25 storm are different phenomena with
// different legitimacy, and smtpd serves both from one process -- #225 already
// showed what shared unkeyed state does there.
func TestCheckPeer_ConnRateIsScopedByListenerRole(t *testing.T) {
	gate, svc, _ := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = 4
		c.ConnRateWindowStr = "1h"
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	// Three on each role: six accepts total, neither role at its threshold.
	for range 3 {
		if _, err := gate.CheckPeer(ctx, ip, true); err != nil {
			t.Fatalf("CheckPeer(auth): %v", err)
		}
		if _, err := gate.CheckPeer(ctx, ip, false); err != nil {
			t.Fatalf("CheckPeer(inbound): %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if got := svc.reportCount(); got != 0 {
		t.Errorf("reports = %d; 3 accepts on each of two roles reached a "+
			"threshold of 4, so the roles are sharing a counter", got)
	}
}

// TestCheckPeer_BannedPeerIsNotRateReported covers the deliberate asymmetry: the
// crossing is still measured, but no RPC is spent on an address whose
// connections are already being refused. Once this signal has a ban threshold
// that also stops the ban being self-renewing -- each ban window's reconnect
// storm would otherwise re-cross and re-ban, making a 24h ban permanent.
func TestCheckPeer_BannedPeerIsNotRateReported(t *testing.T) {
	gate, svc, counts := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = 3
		c.ConnRateWindowStr = "1h"
	})
	ctx := context.Background()
	const ip = "203.0.113.5"
	svc.setBanned(ip, true)

	for range 10 {
		if _, err := gate.CheckPeer(ctx, ip, true); err != nil {
			t.Fatalf("CheckPeer: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if got := svc.reportCount(); got != 0 {
		t.Errorf("reports = %d for an already-banned peer, want 0", got)
	}
	// But the crossing was counted, so the traffic is not invisible.
	if got := counts["suppressed_banned"].Load(); got != 1 {
		t.Errorf("suppressed_banned metric = %d, want 1: the storm must still be "+
			"measurable even though no report was sent", got)
	}
}

// TestCheckPeer_ConnRateDisabled covers the negative-threshold escape hatch.
func TestCheckPeer_ConnRateDisabled(t *testing.T) {
	gate, svc, _ := newReportingGate(t, func(c *Config) {
		c.ConnRateThreshold = -1
	})
	ctx := context.Background()

	for range 100 {
		if _, err := gate.CheckPeer(ctx, "203.0.113.5", true); err != nil {
			t.Fatalf("CheckPeer: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if got := svc.reportCount(); got != 0 {
		t.Errorf("reports = %d with detection disabled, want 0", got)
	}
}

func TestConfig_NormalizeConnRateDefaults(t *testing.T) {
	var c Config
	if err := c.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if c.ConnRateThreshold != DefaultConnRateThreshold {
		t.Errorf("threshold = %d, want %d", c.ConnRateThreshold, DefaultConnRateThreshold)
	}
	if c.ConnRateWindow != DefaultConnRateWindow {
		t.Errorf("window = %v, want %v", c.ConnRateWindow, DefaultConnRateWindow)
	}
}

// TestConfig_NormalizeKeepsNegativeConnRateThreshold pins the convention shared
// with max_tarpit and revoke_after: 0 takes the default, negative disables. A
// Normalize that helpfully replaced the negative with a default would silently
// re-enable something an operator turned off.
func TestConfig_NormalizeKeepsNegativeConnRateThreshold(t *testing.T) {
	c := Config{ConnRateThreshold: -1}
	if err := c.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if c.ConnRateThreshold != -1 {
		t.Errorf("threshold = %d, want -1 preserved", c.ConnRateThreshold)
	}
}

// TestGate_NilGateConnRateIsNoop covers the typed-nil trap. peergate.New returns
// (nil, nil) when disabled, and the daemons assign that to connfork's PeerGate
// interface -- where a nil check on the interface is false. Every method has to
// guard its own receiver.
func TestGate_NilGateConnRateIsNoop(t *testing.T) {
	var gate *Gate
	verdict, err := gate.CheckPeer(context.Background(), "203.0.113.5", true)
	if err != nil {
		t.Fatalf("CheckPeer on a nil gate: %v", err)
	}
	if verdict.Banned || verdict.ShadowBanned {
		t.Errorf("nil gate returned %+v, want the zero verdict", verdict)
	}
}
