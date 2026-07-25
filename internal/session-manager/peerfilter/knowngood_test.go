package peerfilter

import (
	"context"
	"testing"
	"time"
)

func TestRecordGood_SuppressesBan(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	if v := f.Check(ctx, ip); v.Banned {
		t.Error("known-good peer was denied despite a recent successful auth")
	}
}

// TestKnownGood_DoesNotDeleteTheBan matters for measurement: the ban stays on
// record and keeps counting, so `userctl peer list` still shows what policy
// decided even while the exemption is waving it through.
func TestKnownGood_DoesNotDeleteTheBan(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, ip); v.Banned {
		t.Fatal("precondition: expected the ban to be suppressed")
	}

	bans, err := f.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(bans) != 1 || bans[0].Prefix != ip {
		t.Errorf("ban not retained on record: %+v", bans)
	}
}

// TestKnownGood_RevokedAfterThreshold is the bound that keeps one compromised
// credential from being an indefinite bypass.
func TestKnownGood_RevokedAfterThreshold(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) { c.RevokeAfter = 3 })
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	// Three suppressions are allowed.
	for i := range 3 {
		if v := f.Check(ctx, ip); v.Banned {
			t.Fatalf("check %d: denied before the revoke threshold", i+1)
		}
	}

	// The fourth revokes and enforces.
	if v := f.Check(ctx, ip); !v.Banned {
		t.Error("known-good status was not revoked past the threshold")
	}
	// And it stays revoked.
	if v := f.Check(ctx, ip); !v.Banned {
		t.Error("ban not enforced after revocation")
	}
}

func TestKnownGood_RevocationDisabled(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) { c.RevokeAfter = -1 })
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	for i := range 50 {
		if v := f.Check(ctx, ip); v.Banned {
			t.Fatalf("check %d: denied with revocation disabled", i+1)
		}
	}
}

func TestKnownGood_Disabled(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		disabled := false
		c.KnownGood = &disabled
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	// RecordGood is a no-op, and the ban applies.
	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, ip); !v.Banned {
		t.Error("ban suppressed with known_good disabled")
	}
}

// TestKnownGood_ExpiresWithTTL covers the sliding window of trust: an address
// nobody has authenticated from in a long time stops being exempt.
func TestKnownGood_ExpiresWithTTL(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) {
		c.GoodTTL = time.Hour
		c.BanTTL = 24 * time.Hour
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, ip); v.Banned {
		t.Fatal("precondition: expected suppression while known-good is live")
	}

	mr.FastForward(61 * time.Minute)
	if v := f.Check(ctx, ip); !v.Banned {
		t.Error("known-good status outlived its TTL")
	}
}

// TestRecordGood_RefreshesTTL pins the sliding part: each success extends the
// window rather than leaving it on the original deadline.
func TestRecordGood_RefreshesTTL(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) { c.GoodTTL = time.Hour })
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	mr.FastForward(45 * time.Minute)
	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	mr.FastForward(45 * time.Minute)

	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, ip); v.Banned {
		t.Error("known-good expired on the original deadline; the second success did not extend it")
	}
}

func TestRecordGood_AllowlistedPeerIsSkipped(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.Allowlist = []string{"10.0.0.0/8"}
	})
	ctx := context.Background()

	if err := f.RecordGood(ctx, "10.1.2.3"); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	entries, err := f.ListGood(ctx)
	if err != nil {
		t.Fatalf("ListGood: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("allowlisted peer recorded as known-good: %+v", entries)
	}
}

func TestRecordGood_RejectsUnparseableAddress(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	if err := f.RecordGood(context.Background(), "not-an-address"); err == nil {
		t.Error("unparseable address accepted")
	}
}

func TestRecordGood_NilFilter(t *testing.T) {
	var f *Filter
	if err := f.RecordGood(context.Background(), "203.0.113.5"); err != nil {
		t.Errorf("RecordGood on nil filter: %v", err)
	}
	if entries, err := f.ListGood(context.Background()); err != nil || entries != nil {
		t.Errorf("ListGood on nil filter = %v, %v", entries, err)
	}
}

// TestKnownGood_IPv6SharesPrefixWithBan keeps the two keyspaces consistent: a
// successful auth from one address in a /64 exempts the /64, because that is
// also the unit a ban applies to.
func TestKnownGood_IPv6SharesPrefixWithBan(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()

	if err := f.RecordGood(ctx, "2001:db8:aa:bb::1"); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, "2001:db8:aa:bb:cafe::9", "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, "2001:db8:aa:bb:dead::7"); v.Banned {
		t.Error("known-good /64 did not suppress a ban earned by a sibling address")
	}
}

// TestListGood_ReportsBothSides is the measurement the feature exists to
// enable: how many real logins an address has, and how many bans its exemption
// has waved through.
func TestListGood_ReportsBothSides(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.GoodTTL = 24 * time.Hour
		c.RevokeAfter = -1
	})
	ctx := context.Background()
	ip := "203.0.113.5"

	for range 3 {
		if err := f.RecordGood(ctx, ip); err != nil {
			t.Fatalf("RecordGood: %v", err)
		}
	}
	if err := f.Ban(ctx, ip, "nonexistent_account"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	for range 2 {
		f.Check(ctx, ip)
	}

	entries, err := f.ListGood(ctx)
	if err != nil {
		t.Fatalf("ListGood: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ListGood returned %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Prefix != ip {
		t.Errorf("prefix = %q", got.Prefix)
	}
	if got.SuccessfulAuths != 3 {
		t.Errorf("successful auths = %d, want 3", got.SuccessfulAuths)
	}
	if got.SuppressedBans != 2 {
		t.Errorf("suppressed bans = %d, want 2", got.SuppressedBans)
	}
	if got.TTL <= 0 || got.TTL > 24*time.Hour {
		t.Errorf("TTL = %v, want (0, 24h]", got.TTL)
	}
}

// TestUnban_ClearsSuppressionCounter keeps an operator's unban from leaving the
// address one suppression away from losing its known-good status.
func TestUnban_ClearsSuppressionCounter(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) { c.RevokeAfter = 2 })
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	f.Check(ctx, ip)
	f.Check(ctx, ip)

	if _, err := f.Unban(ctx, ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}

	entries, err := f.ListGood(ctx)
	if err != nil {
		t.Fatalf("ListGood: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("known-good record lost on unban: %+v", entries)
	}
	if entries[0].SuppressedBans != 0 {
		t.Errorf("suppressed bans = %d after unban, want 0", entries[0].SuppressedBans)
	}
}

// TestKnownGood_LookupFailureEnforcesBan pins the fail-direction for the
// exemption specifically. It is the opposite of Check's overall fail-open: the
// address is banned on evidence, and the exemption is a courtesy that should not
// be granted on a guess.
func TestKnownGood_LookupFailureEnforcesBan(t *testing.T) {
	f, mr := newTestFilter(t, nil)
	ctx := context.Background()
	ip := "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	// With Redis gone, Check's own ban lookup fails first and fails open, so
	// drive suppressBan directly to exercise its failure path.
	mr.Close()
	if f.suppressBan(ctx, ip) {
		t.Error("suppressBan granted an exemption while the store was unreachable")
	}
}

func TestConfig_KnownGoodDefaults(t *testing.T) {
	var cfg Config
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !cfg.KnownGoodEnabled() {
		t.Error("known-good disabled by default; it should ship on")
	}
	d := Defaults()
	if cfg.GoodTTL != d.GoodTTL {
		t.Errorf("GoodTTL = %v, want %v", cfg.GoodTTL, d.GoodTTL)
	}
	if cfg.RevokeAfter != d.RevokeAfter {
		t.Errorf("RevokeAfter = %d, want %d", cfg.RevokeAfter, d.RevokeAfter)
	}
}

func TestConfig_KnownGoodNormalize(t *testing.T) {
	cfg := Config{GoodTTLStr: "48h", RevokeAfter: 3}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.GoodTTL != 48*time.Hour {
		t.Errorf("GoodTTL = %v, want 48h", cfg.GoodTTL)
	}
	if cfg.RevokeAfter != 3 {
		t.Errorf("RevokeAfter = %d, want 3", cfg.RevokeAfter)
	}

	// Negative survives normalization: it means "never revoke".
	cfg = Config{RevokeAfter: -1}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.RevokeAfter != -1 {
		t.Errorf("RevokeAfter = %d, want -1 preserved", cfg.RevokeAfter)
	}
}
