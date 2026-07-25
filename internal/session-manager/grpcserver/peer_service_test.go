package grpcserver

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/redis/go-redis/v9"
)

// newPeerTestServer builds a sessionServer wired to a real peerfilter over
// miniredis. mgr stays nil: CheckPeer and ReportPeer never touch it.
func newPeerTestServer(t *testing.T, override func(*peerfilter.Config)) (*sessionServer, *peerfilter.Filter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	cfg := peerfilter.Defaults()
	if override != nil {
		override(&cfg)
	}
	filter, err := peerfilter.New(cfg, client, nil)
	if err != nil {
		t.Fatalf("peerfilter.New: %v", err)
	}
	return &sessionServer{filter: filter}, filter, mr
}

func TestCheckPeer_AllowsUnbannedPeer(t *testing.T) {
	srv, _, _ := newPeerTestServer(t, nil)

	resp, err := srv.CheckPeer(context.Background(), &smpb.CheckPeerRequest{Ip: "203.0.113.5", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if resp.Banned {
		t.Error("unbanned peer reported as banned")
	}
	if resp.TarpitMs != 0 {
		t.Errorf("tarpit_ms = %d for an allowed peer, want 0", resp.TarpitMs)
	}
}

func TestCheckPeer_DeniesBannedPeerWithTarpit(t *testing.T) {
	srv, filter, _ := newPeerTestServer(t, func(c *peerfilter.Config) {
		c.AcceptTarpit = 30 * time.Second
	})
	ctx := context.Background()

	if err := filter.Ban(ctx, "203.0.113.5", "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	resp, err := srv.CheckPeer(ctx, &smpb.CheckPeerRequest{Ip: "203.0.113.5", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if !resp.Banned {
		t.Fatal("banned peer reported as allowed")
	}
	if resp.TarpitMs != 30_000 {
		t.Errorf("tarpit_ms = %d, want 30000", resp.TarpitMs)
	}
	// The wire reason must be the coarse label, never the stored detail --
	// otherwise a daemon's logs leak which signal fired, and the verdict
	// becomes an enumeration side channel.
	if resp.Reason != peerfilter.ReasonBanned {
		t.Errorf("reason = %q, want %q", resp.Reason, peerfilter.ReasonBanned)
	}
	if resp.Reason == "nonexistent_account" {
		t.Error("wire reason leaked the stored ban detail")
	}
}

// TestCheckPeer_EmptyIPIsAllowed covers the hot-path contract: the dispatcher
// gets an allow rather than an error for input it cannot act on.
func TestCheckPeer_EmptyIPIsAllowed(t *testing.T) {
	srv, _, _ := newPeerTestServer(t, nil)

	resp, err := srv.CheckPeer(context.Background(), &smpb.CheckPeerRequest{Ip: "", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer with empty ip returned an error: %v", err)
	}
	if resp.Banned {
		t.Error("empty ip denied")
	}
}

// TestCheckPeer_NilFilterAllows is what makes the feature safe to ship
// disabled: with no filter configured every peer is served.
func TestCheckPeer_NilFilterAllows(t *testing.T) {
	srv := &sessionServer{}

	resp, err := srv.CheckPeer(context.Background(), &smpb.CheckPeerRequest{Ip: "203.0.113.5", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if resp.Banned {
		t.Error("nil filter denied a peer")
	}
}

func TestReportPeer_BansAtThreshold(t *testing.T) {
	srv, _, _ := newPeerTestServer(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{"early_talker": 2}
	})
	ctx := context.Background()
	req := &smpb.ReportPeerRequest{Ip: "203.0.113.5", Signal: "early_talker"}

	if _, err := srv.ReportPeer(ctx, req); err != nil {
		t.Fatalf("ReportPeer: %v", err)
	}
	resp, err := srv.CheckPeer(ctx, &smpb.CheckPeerRequest{Ip: "203.0.113.5", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if resp.Banned {
		t.Fatal("banned after one report, threshold is 2")
	}

	if _, err := srv.ReportPeer(ctx, req); err != nil {
		t.Fatalf("ReportPeer: %v", err)
	}
	resp, err = srv.CheckPeer(ctx, &smpb.CheckPeerRequest{Ip: "203.0.113.5", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if !resp.Banned {
		t.Error("not banned after reaching the threshold")
	}
}

func TestReportPeer_RequiresIPAndSignal(t *testing.T) {
	srv, _, _ := newPeerTestServer(t, nil)
	ctx := context.Background()

	if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{Signal: "early_talker"}); err == nil {
		t.Error("missing ip accepted")
	}
	if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{Ip: "203.0.113.5"}); err == nil {
		t.Error("missing signal accepted")
	}
}

// TestReportPeer_StoreFailureIsNotFatal pins the decision that losing an abuse
// count is cheaper than failing the caller's connection.
func TestReportPeer_StoreFailureIsNotFatal(t *testing.T) {
	srv, _, mr := newPeerTestServer(t, nil)
	ctx := context.Background()

	// Take Redis away underneath the filter.
	mr.Close()

	if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{
		Ip: "203.0.113.5", Signal: "early_talker",
	}); err != nil {
		t.Errorf("ReportPeer returned an error on store failure: %v", err)
	}
}

// TestCheckPeer_IPv6UsesPrefix confirms the /64 normalization reaches the RPC
// boundary, not just the policy layer.
func TestCheckPeer_IPv6UsesPrefix(t *testing.T) {
	srv, filter, _ := newPeerTestServer(t, nil)
	ctx := context.Background()

	if err := filter.Ban(ctx, "2001:db8:aa:bb::1", "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	resp, err := srv.CheckPeer(ctx, &smpb.CheckPeerRequest{Ip: "2001:db8:aa:bb:cafe::9", AuthFacing: true})
	if err != nil {
		t.Fatalf("CheckPeer: %v", err)
	}
	if !resp.Banned {
		t.Error("sibling address in the banned /64 was allowed")
	}
}
