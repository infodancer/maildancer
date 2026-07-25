package grpcserver

import (
	"context"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/peersignal"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
)

// validate is a shorthand for one ValidateRecipient call.
func validate(t *testing.T, srv *sessionServer, address, ip string) *smpb.ValidateRecipientResponse {
	t.Helper()
	resp, err := srv.ValidateRecipient(context.Background(), &smpb.ValidateRecipientRequest{
		Address:  address,
		ClientIp: ip,
	})
	if err != nil {
		t.Fatalf("ValidateRecipient(%s): %v", address, err)
	}
	return resp
}

// TestValidateRecipient_InvalidRecipientBansAtThreshold is rule 3's recipient
// dictionary attack. Unlike rule 1 this is a counted rate, not a first-attempt
// ban: legitimate senders do write to retired addresses.
func TestValidateRecipient_InvalidRecipientBansAtThreshold(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.5"

	// The wiring provider hosts example.com, so a miss there is a local-domain
	// miss -- the case that counts. Tighten the threshold to keep the test quick.
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{peersignal.InvalidRecipient: 3}
	})

	for i := range 2 {
		validate(t, srv, "nosuchuser@example.com", ip)
		if v := srv.filter.Check(ctx, ip); v.Banned {
			t.Fatalf("banned after %d invalid recipients, threshold is 3", i+1)
		}
	}

	validate(t, srv, "nosuchuser@example.com", ip)
	if v := srv.filter.Check(ctx, ip); !v.Banned {
		t.Error("not banned after reaching the invalid-recipient threshold")
	}
}

// TestValidateRecipient_ValidRecipientIsNotAbuse guards the obvious regression:
// ordinary mail must not accrue abuse counts.
func TestValidateRecipient_ValidRecipientIsNotAbuse(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{peersignal.InvalidRecipient: 2}
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	// alice is the one real account in the wiring agent.
	for range 10 {
		resp := validate(t, srv, "alice@example.com", ip)
		if !resp.UserExists {
			t.Fatal("precondition: expected the recipient to exist")
		}
	}

	if v := srv.filter.Check(ctx, ip); v.Banned {
		t.Error("valid recipients produced an abuse ban")
	}
}

// TestValidateRecipient_NonLocalDomainIsNotAbuse pins a deliberate exclusion: a
// message for a domain we do not host is misdirected mail, not probing of our
// address space. Counting it would ban anyone whose forwarding is misconfigured.
func TestValidateRecipient_NonLocalDomainIsNotAbuse(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{peersignal.InvalidRecipient: 2}
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	for range 10 {
		resp := validate(t, srv, "someone@notourdomain.test", ip)
		if resp.DomainIsLocal {
			t.Fatal("precondition: expected a non-local domain")
		}
	}

	if v := srv.filter.Check(ctx, ip); v.Banned {
		t.Error("recipients on a non-local domain produced an abuse ban")
	}
}

// TestValidateRecipient_NoClientIPRecordsNothing covers the degenerate case: an
// older daemon that does not send the address must still get a working answer.
func TestValidateRecipient_NoClientIPRecordsNothing(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{peersignal.InvalidRecipient: 1}
	})

	resp, err := srv.ValidateRecipient(context.Background(), &smpb.ValidateRecipientRequest{
		Address: "nosuchuser@example.com",
	})
	if err != nil {
		t.Fatalf("ValidateRecipient: %v", err)
	}
	if !resp.DomainIsLocal {
		t.Error("expected a local domain")
	}

	bans, err := srv.filter.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(bans) != 0 {
		t.Errorf("bans recorded with no client IP: %+v", bans)
	}
}

// TestReportPeer_RelayDeniedBansAtThreshold covers the signal smtpd reports
// itself: an unauthenticated client asking us to relay to a foreign domain is
// probing for an open relay.
func TestReportPeer_RelayDeniedBansAtThreshold(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{peersignal.RelayDenied: 3}
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	for i := range 2 {
		if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{
			Ip: ip, Signal: peersignal.RelayDenied,
		}); err != nil {
			t.Fatalf("ReportPeer %d: %v", i, err)
		}
		if v := srv.filter.Check(ctx, ip); v.Banned {
			t.Fatalf("banned after %d relay attempts, threshold is 3", i+1)
		}
	}

	if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{
		Ip: ip, Signal: peersignal.RelayDenied,
	}); err != nil {
		t.Fatalf("ReportPeer: %v", err)
	}
	if v := srv.filter.Check(ctx, ip); !v.Banned {
		t.Error("not banned after reaching the relay-denied threshold")
	}
}

// TestRule3_SignalsCountSeparately keeps one signal's traffic from tipping
// another's threshold.
func TestRule3_SignalsCountSeparately(t *testing.T) {
	srv, _ := newTimingServer(t, 0)
	srv.filter = rebuildFilter(t, func(c *peerfilter.Config) {
		c.AbuseThresholds = map[string]int{
			peersignal.InvalidRecipient: 2,
			peersignal.RelayDenied:      2,
		}
	})
	ctx := context.Background()
	const ip = "203.0.113.5"

	validate(t, srv, "nosuchuser@example.com", ip)
	if _, err := srv.ReportPeer(ctx, &smpb.ReportPeerRequest{
		Ip: ip, Signal: peersignal.RelayDenied,
	}); err != nil {
		t.Fatalf("ReportPeer: %v", err)
	}

	if v := srv.filter.Check(ctx, ip); v.Banned {
		t.Error("one occurrence of each of two signals reached a threshold")
	}
}

// TestRule3_DefaultThresholdsAreSet is the secure-by-default assertion for rule
// 3: with no abuse_thresholds table configured, the signals still have
// thresholds and therefore still ban.
func TestRule3_DefaultThresholdsAreSet(t *testing.T) {
	var cfg peerfilter.Config
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	for _, signal := range []string{peersignal.InvalidRecipient, peersignal.RelayDenied} {
		if n := cfg.AbuseThresholds[signal]; n <= 0 {
			t.Errorf("%s has no default threshold; rule 3 would never ban", signal)
		}
	}
}

// TestRule3_ExplicitEmptyTableDisablesSignals pins the other half: an operator
// who writes an empty table means it, and defaults must not be merged back in.
func TestRule3_ExplicitEmptyTableDisablesSignals(t *testing.T) {
	cfg := peerfilter.Config{AbuseThresholds: map[string]int{}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(cfg.AbuseThresholds) != 0 {
		t.Errorf("defaults were merged into an explicitly empty table: %+v", cfg.AbuseThresholds)
	}
}

// rebuildFilter returns a fresh filter over its own miniredis with the given
// config overrides, so each test starts from an empty keyspace.
func rebuildFilter(t *testing.T, override func(*peerfilter.Config)) *peerfilter.Filter {
	t.Helper()
	cfg := peerfilter.Defaults()
	cfg.AbuseWindow = time.Hour
	if override != nil {
		override(&cfg)
	}
	filter, _ := newFilterOverMiniredis(t, cfg)
	return filter
}
