package peerfilter

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// newTestFilter builds a Filter over an in-process miniredis with the default
// policy, plus any config overrides the test needs. No metrics: most tests are
// about policy, and a shared registry across tests would accumulate counts.
func newTestFilter(t *testing.T, override func(*Config)) (*Filter, *miniredis.Miniredis) {
	t.Helper()
	return newTestFilterWithRegistry(t, nil, override)
}

// newTestFilterWithRegistry is newTestFilter with the ban-decision series
// registered against reg, so a test can assert on them. Each test passes its
// own registry; the default one would carry counts between tests.
func newTestFilterWithRegistry(t *testing.T, reg prometheus.Registerer, override func(*Config)) (*Filter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	cfg := Defaults()
	if override != nil {
		override(&cfg)
	}
	f, err := New(cfg, client, nil, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f == nil {
		t.Fatal("New returned a nil filter for an enabled config")
	}
	return f, mr
}

func TestNormalizePrefix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4", "203.0.113.5", "203.0.113.5"},
		{"ipv4 in ipv6 form", "::ffff:203.0.113.5", "203.0.113.5"},
		{"ipv6 to /64", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"ipv6 already on the boundary", "2001:db8:1:2::", "2001:db8:1:2::/64"},
		{"ipv6 loopback", "::1", "::/64"},
		{"garbage", "not-an-address", ""},
		{"empty", "", ""},
		{"hostport not accepted", "203.0.113.5:993", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePrefix(tc.in); got != tc.want {
				t.Errorf("NormalizePrefix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestIPv6SiblingsShareABan is the reason NormalizePrefix exists: banning
// single v6 addresses is theater, because cycling addresses inside an
// allocation is free to the attacker.
func TestIPv6SiblingsShareABan(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()

	if err := f.Ban(ctx, "2001:db8:1:2:3:4:5:6", "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	if v := f.Check(ctx, "2001:db8:1:2:ffff:ffff:ffff:ffff", true); !v.Banned {
		t.Error("sibling address in the same /64 is not banned")
	}
	// A different /64 must be unaffected.
	if v := f.Check(ctx, "2001:db8:1:3::1", true); v.Banned {
		t.Error("a different /64 was caught by the ban")
	}
}

func TestNew_DisabledReturnsNilFilter(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cfg := Defaults()
	disabled := false
	cfg.Enabled = &disabled
	f, err := New(cfg, client, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f.Enabled() {
		t.Error("disabled config produced an enabled filter")
	}
	// A nil filter must be safe to use and must allow everything, so callers
	// need no nil check of their own.
	if v := f.Check(context.Background(), "203.0.113.5", true); v.Banned {
		t.Error("nil filter banned a peer")
	}
	if err := f.Ban(context.Background(), "203.0.113.5", "x"); err != nil {
		t.Errorf("Ban on nil filter: %v", err)
	}
	if _, err := f.Unban(context.Background(), "203.0.113.5"); err != nil {
		t.Errorf("Unban on nil filter: %v", err)
	}
	if entries, err := f.List(context.Background()); err != nil || entries != nil {
		t.Errorf("List on nil filter = %v, %v", entries, err)
	}
}

// TestNew_NilClientDisables pins the deliberate difference from the
// authentication limiter, which falls back to an in-process store: an
// accept-time ban is worthless per-process, so with no Redis the filter is off.
func TestNew_NilClientDisables(t *testing.T) {
	f, err := New(Defaults(), nil, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f.Enabled() {
		t.Error("nil Redis client produced an enabled filter")
	}
}

// TestNew_InvalidAllowlistIsAnError guards the operator's escape hatch: a typo
// in the allowlist must be loud, because silently dropping the entry is how an
// admin gets locked out of their own mail server.
func TestNew_InvalidAllowlistIsAnError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cfg := Defaults()
	cfg.Allowlist = []string{"10.0.0.0/8", "not-a-cidr"}
	if _, err := New(cfg, client, nil, nil); err == nil {
		t.Error("invalid allowlist CIDR accepted")
	}
}

func TestCheck_UnbannedPeerIsAllowed(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	if v := f.Check(context.Background(), "203.0.113.5", true); v.Banned {
		t.Error("peer with no ban was denied")
	}
}

func TestBanAndCheck(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()

	if err := f.Ban(ctx, "203.0.113.5", "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	v := f.Check(ctx, "203.0.113.5", true)
	if !v.Banned {
		t.Fatal("banned peer was allowed")
	}
	if v.Tarpit != 30*time.Second {
		t.Errorf("tarpit = %v, want 30s", v.Tarpit)
	}
	// The reason returned to daemons must be the coarse label, never the
	// signal that fired -- otherwise the verdict is an enumeration side channel.
	if v.Reason != ReasonBanned {
		t.Errorf("reason = %q, want %q", v.Reason, ReasonBanned)
	}
}

func TestBan_ReleasesOnTTL(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) { c.BanTTL = time.Hour })
	ctx := context.Background()

	if err := f.Ban(ctx, "203.0.113.5", "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	mr.FastForward(61 * time.Minute)

	if v := f.Check(ctx, "203.0.113.5", true); v.Banned {
		t.Error("ban outlived its TTL; nothing sweeps it")
	}
}

// TestBan_EscalatesForRepeatOffender covers the strike path: an address that
// serves a full ban and comes back gets the longer TTL, because strikes outlive
// bans.
func TestBan_EscalatesForRepeatOffender(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) {
		c.BanTTL = time.Hour
		c.BanTTLRepeat = 24 * time.Hour
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.Ban(ctx, ip, "first"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if ttl := mr.TTL(keyBan + ip); ttl != time.Hour {
		t.Fatalf("first ban TTL = %v, want 1h", ttl)
	}

	// Serve the ban out, then reoffend.
	mr.FastForward(61 * time.Minute)
	if err := f.Ban(ctx, ip, "second"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if ttl := mr.TTL(keyBan + ip); ttl != 24*time.Hour {
		t.Errorf("repeat ban TTL = %v, want 24h", ttl)
	}
}

func TestBan_FlatPolicyWhenTTLsMatch(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) {
		c.BanTTL = time.Hour
		c.BanTTLRepeat = time.Hour
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	for range 3 {
		if err := f.Ban(ctx, ip, "test"); err != nil {
			t.Fatalf("Ban: %v", err)
		}
	}
	if ttl := mr.TTL(keyBan + ip); ttl != time.Hour {
		t.Errorf("TTL = %v, want 1h with escalation disabled", ttl)
	}
}

// TestAllowlist_NeverBannedNeverChecked is the safety property that matters
// most: a policy bug must not be able to lock the operator out.
func TestAllowlist_NeverBannedNeverChecked(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.Allowlist = []string{"127.0.0.0/8", "10.0.0.0/8", "::1/128"}
	})
	ctx := context.Background()

	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "::1"} {
		if !f.Allowed(ip) {
			t.Errorf("%s not recognized as allowlisted", ip)
		}
		if err := f.Ban(ctx, ip, "test"); err != nil {
			t.Fatalf("Ban(%s): %v", ip, err)
		}
		if v := f.Check(ctx, ip, true); v.Banned {
			t.Errorf("allowlisted %s was banned", ip)
		}
	}

	// An address outside the allowlist is still bannable.
	if f.Allowed("203.0.113.5") {
		t.Error("public address reported as allowlisted")
	}
}

func TestUnban(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.Ban(ctx, ip, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	removed, err := f.Unban(ctx, ip)
	if err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if !removed {
		t.Error("Unban reported no ban present")
	}
	if v := f.Check(ctx, ip, true); v.Banned {
		t.Error("peer still banned after Unban")
	}

	// Unbanning something that was never banned is not an error.
	removed, err = f.Unban(ctx, "198.51.100.1")
	if err != nil {
		t.Fatalf("Unban of unbanned peer: %v", err)
	}
	if removed {
		t.Error("Unban reported a removal for an unbanned peer")
	}
}

// TestUnban_ClearsStrikes pins the operator-intent decision: undoing a false
// positive must not leave the address one strike from a week-long ban.
func TestUnban_ClearsStrikes(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) {
		c.BanTTL = time.Hour
		c.BanTTLRepeat = 24 * time.Hour
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.Ban(ctx, ip, "false positive"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if _, err := f.Unban(ctx, ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}

	// A later ban must be treated as a first offense again.
	if err := f.Ban(ctx, ip, "real"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if ttl := mr.TTL(keyBan + ip); ttl != time.Hour {
		t.Errorf("post-unban ban TTL = %v, want the first-offense 1h", ttl)
	}
}

func TestReport_BansAtThreshold(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.AbuseThresholds = map[string]int{"early_talker": 3}
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	for i := range 2 {
		if err := f.Report(ctx, ip, "early_talker"); err != nil {
			t.Fatalf("Report %d: %v", i, err)
		}
		if v := f.Check(ctx, ip, true); v.Banned {
			t.Fatalf("banned after %d reports, threshold is 3", i+1)
		}
	}

	if err := f.Report(ctx, ip, "early_talker"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if v := f.Check(ctx, ip, true); !v.Banned {
		t.Error("not banned after reaching the threshold")
	}
}

// TestReport_UnknownSignalNeverBans keeps a daemon from inventing a signal name
// and getting an unconfigured ban policy for free.
func TestReport_UnknownSignalNeverBans(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.AbuseThresholds = map[string]int{"early_talker": 2}
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	for range 50 {
		if err := f.Report(ctx, ip, "something_made_up"); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}
	if v := f.Check(ctx, ip, true); v.Banned {
		t.Error("an unconfigured signal produced a ban")
	}
}

func TestReport_SignalsCountedSeparately(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.AbuseThresholds = map[string]int{"early_talker": 2, "data_abort": 2}
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.Report(ctx, ip, "early_talker"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if err := f.Report(ctx, ip, "data_abort"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if v := f.Check(ctx, ip, true); v.Banned {
		t.Error("one occurrence of each of two signals should not reach either threshold")
	}
}

func TestReport_CounterExpiresWithWindow(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) {
		c.AbuseThresholds = map[string]int{"early_talker": 3}
		c.AbuseWindow = time.Hour
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	for range 2 {
		if err := f.Report(ctx, ip, "early_talker"); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}
	mr.FastForward(61 * time.Minute)

	// A third report after the window must start a fresh count, not tip the
	// threshold using occurrences from an hour ago.
	if err := f.Report(ctx, ip, "early_talker"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if v := f.Check(ctx, ip, true); v.Banned {
		t.Error("abuse counter did not expire with its window")
	}
}

func TestReport_EmptySignalIsAnError(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	if err := f.Report(context.Background(), "203.0.113.5", ""); err == nil {
		t.Error("empty signal accepted")
	}
}

func TestReport_AllowlistedPeerIsIgnored(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.Allowlist = []string{"10.0.0.0/8"}
		c.AbuseThresholds = map[string]int{"early_talker": 1}
	})
	ctx := context.Background()

	if err := f.Report(ctx, "10.1.2.3", "early_talker"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if v := f.Check(ctx, "10.1.2.3", true); v.Banned {
		t.Error("allowlisted peer banned via Report")
	}
}

func TestList(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) { c.BanTTL = 2 * time.Hour })
	ctx := context.Background()

	for _, ip := range []string{"203.0.113.5", "198.51.100.7"} {
		if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
			t.Fatalf("Ban(%s): %v", ip, err)
		}
	}

	entries, err := f.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}

	byPrefix := make(map[string]BanEntry, len(entries))
	for _, e := range entries {
		byPrefix[e.Prefix] = e
	}
	got, ok := byPrefix["203.0.113.5"]
	if !ok {
		t.Fatalf("203.0.113.5 missing from listing: %+v", entries)
	}
	if got.Reason != "nonexistent_account" {
		t.Errorf("reason = %q, want the stored label", got.Reason)
	}
	if got.TTL <= 0 || got.TTL > 2*time.Hour {
		t.Errorf("TTL = %v, want (0, 2h]", got.TTL)
	}
	if got.Strikes != 1 {
		t.Errorf("strikes = %d, want 1", got.Strikes)
	}
}

func TestList_EmptyWhenNoBans(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	entries, err := f.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List returned %d entries on an empty store", len(entries))
	}
}

// TestCheck_FailsOpenOnRedisError pins the fail-open decision for the gate: a
// Redis outage must not refuse every connection on every daemon, which is what
// failing closed here would do.
func TestCheck_FailsOpenOnRedisError(t *testing.T) {
	f, mr := newTestFilter(t, nil)
	ctx := context.Background()

	if err := f.Ban(ctx, "203.0.113.5", "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, "203.0.113.5", true); !v.Banned {
		t.Fatal("precondition: peer should be banned")
	}

	mr.Close()
	if v := f.Check(ctx, "203.0.113.5", true); v.Banned {
		t.Error("Check failed closed on a Redis error; must fail open")
	}
}

func TestCheck_UnparseableAddressIsAllowed(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	// Not a security hole: an address we cannot parse cannot be matched
	// against a ban either, and refusing it would break on any future
	// address form we do not yet handle.
	if v := f.Check(context.Background(), "garbage", true); v.Banned {
		t.Error("unparseable address was denied")
	}
}

func TestConfig_Normalize(t *testing.T) {
	cfg := Config{
		Enabled:         boolPtr(true),
		BanTTLStr:       "12h",
		BanTTLRepeatStr: "72h",
		AcceptTarpitStr: "10s",
		AbuseWindowStr:  "30m",
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.BanTTL != 12*time.Hour {
		t.Errorf("BanTTL = %v, want 12h", cfg.BanTTL)
	}
	if cfg.BanTTLRepeat != 72*time.Hour {
		t.Errorf("BanTTLRepeat = %v, want 72h", cfg.BanTTLRepeat)
	}
	if cfg.AcceptTarpit != 10*time.Second {
		t.Errorf("AcceptTarpit = %v, want 10s", cfg.AcceptTarpit)
	}
	if cfg.AbuseWindow != 30*time.Minute {
		t.Errorf("AbuseWindow = %v, want 30m", cfg.AbuseWindow)
	}
}

func TestConfig_NormalizeFillsDefaults(t *testing.T) {
	cfg := Config{Enabled: boolPtr(true)}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	d := Defaults()
	if cfg.BanTTL != d.BanTTL || cfg.BanTTLRepeat != d.BanTTLRepeat ||
		cfg.AcceptTarpit != d.AcceptTarpit || cfg.AbuseWindow != d.AbuseWindow {
		t.Errorf("Normalize did not fill defaults: %+v", cfg)
	}
}

// TestConfig_NormalizeAllowsZeroTarpit covers the one duration where zero is a
// deliberate choice (close immediately) rather than "unset".
func TestConfig_NormalizeAllowsZeroTarpit(t *testing.T) {
	cfg := Config{Enabled: boolPtr(true), AcceptTarpitStr: "0s"}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.AcceptTarpit != 0 {
		t.Errorf("AcceptTarpit = %v, want 0 when explicitly configured as 0s", cfg.AcceptTarpit)
	}
}

func TestConfig_NormalizeRejectsBadDuration(t *testing.T) {
	cfg := Config{Enabled: boolPtr(true), BanTTLStr: "forever"}
	if err := cfg.Normalize(); err == nil {
		t.Error("invalid duration accepted")
	}
}

// boolPtr is a helper for the pointer-valued Enabled field.
func boolPtr(b bool) *bool { return &b }
