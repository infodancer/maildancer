package peerfilter

import (
	"context"
	"testing"
	"time"
)

// TestCheck_AuthDerivedBanShadowsOnInboundSMTP is the core of #225. Rule 1 bans
// on a single attempt against a nonexistent account, which is airtight evidence
// about authentication and much weaker evidence about sending reputation. On a
// listener where nobody authenticates the ban is recorded, not enforced --
// refusing inbound mail on that basis destroys a third party's message.
func TestCheck_AuthDerivedBanShadowsOnInboundSMTP(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	// Auth-facing listener: enforced.
	if v := f.Check(ctx, ip, true); !v.Banned {
		t.Error("auth-derived ban not enforced on an auth-facing listener")
	}

	// Inbound SMTP: recorded, not enforced.
	v := f.Check(ctx, ip, false)
	if v.Banned {
		t.Error("auth-derived ban enforced on inbound SMTP; a third party's mail would be refused")
	}
	if !v.ShadowBanned {
		t.Error("auth-derived ban on inbound SMTP was not reported as a shadow ban, so nothing is measurable")
	}
	if v.Tarpit != 0 {
		t.Errorf("tarpit = %v on a served connection, want 0", v.Tarpit)
	}
}

// TestCheck_AbuseBanEnforcesEverywhere is the other half: rule 3's evidence is
// SMTP-native -- the address demonstrated the behaviour on the port being
// refused -- so it enforces on every listener.
func TestCheck_AbuseBanEnforcesEverywhere(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, ReasonAbuse+":relay_denied"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	for _, authFacing := range []bool{true, false} {
		v := f.Check(ctx, ip, authFacing)
		if !v.Banned {
			t.Errorf("abuse ban not enforced (auth_facing=%v)", authFacing)
		}
		if v.ShadowBanned {
			t.Errorf("abuse ban reported as shadow (auth_facing=%v)", authFacing)
		}
	}
}

// TestCheck_ManualBanEnforcesEverywhere keeps operator intent absolute. If
// someone bans an address by hand they mean it, on every port.
func TestCheck_ManualBanEnforcesEverywhere(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, ReasonManual); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	for _, authFacing := range []bool{true, false} {
		if v := f.Check(ctx, ip, authFacing); !v.Banned {
			t.Errorf("manual ban not enforced (auth_facing=%v)", authFacing)
		}
	}
}

// TestCheck_UnknownReasonEnforcesEverywhere pins the fail-toward-stricter rule:
// a reason nobody has classified keeps enforcing, so adding a new ban source
// without touching the scope table cannot silently stop protecting anything.
func TestCheck_UnknownReasonEnforcesEverywhere(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, "some_future_signal"); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	if v := f.Check(ctx, ip, false); !v.Banned {
		t.Error("unclassified ban reason was shadowed; it should fail toward enforcing")
	}
}

// TestCheck_AuthBanScopeAll restores the pre-#225 behaviour for a deployment
// that decides, on data, that it wants inbound SMTP refused too.
func TestCheck_AuthBanScopeAll(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) { c.AuthBanScope = AuthBanScopeAll })
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	v := f.Check(ctx, ip, false)
	if !v.Banned {
		t.Error("auth_ban_scope=all did not enforce on inbound SMTP")
	}
	if v.ShadowBanned {
		t.Error("enforced ban also reported as shadow")
	}
	if v.Tarpit == 0 {
		t.Error("enforced ban carries no tarpit")
	}
}

// TestCheck_ShadowBanRespectsKnownGood keeps the two mechanisms from
// double-counting: a known-good address is exempt outright, so there is nothing
// to shadow-report about it.
func TestCheck_ShadowBanRespectsKnownGood(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	if err := f.Ban(ctx, ip, ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	v := f.Check(ctx, ip, false)
	if v.Banned || v.ShadowBanned {
		t.Errorf("known-good peer produced %+v; the exemption should short-circuit first", v)
	}
}

// TestCheck_AllowlistedPeerIsNeverShadowed guards the same boundary for the
// allowlist: an exempt address must not generate shadow noise either.
func TestCheck_AllowlistedPeerIsNeverShadowed(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.Allowlist = []string{"10.0.0.0/8"}
	})
	ctx := context.Background()

	if err := f.Ban(ctx, "10.1.2.3", ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, "10.1.2.3", false); v.Banned || v.ShadowBanned {
		t.Errorf("allowlisted peer produced %+v", v)
	}
}

// TestCheck_ShadowedBanStillExpires confirms shadow mode changes enforcement
// only: the underlying ban is an ordinary one with an ordinary TTL.
func TestCheck_ShadowedBanStillExpires(t *testing.T) {
	f, mr := newTestFilter(t, func(c *Config) { c.BanTTL = time.Hour })
	ctx := context.Background()
	const ip = "203.0.113.5"

	if err := f.Ban(ctx, ip, ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if v := f.Check(ctx, ip, false); !v.ShadowBanned {
		t.Fatal("precondition: expected a shadow ban")
	}

	mr.FastForward(61 * time.Minute)
	if v := f.Check(ctx, ip, false); v.ShadowBanned || v.Banned {
		t.Error("ban outlived its TTL in shadow mode")
	}
}

func TestConfig_AuthBanScopeDefaultAndValidation(t *testing.T) {
	var cfg Config
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.AuthBanScope != AuthBanScopeAuthListeners {
		t.Errorf("default auth_ban_scope = %q, want %q",
			cfg.AuthBanScope, AuthBanScopeAuthListeners)
	}

	cfg = Config{AuthBanScope: AuthBanScopeAll}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize with 'all': %v", err)
	}
	if cfg.AuthBanScope != AuthBanScopeAll {
		t.Errorf("explicit 'all' was overwritten with %q", cfg.AuthBanScope)
	}

	cfg = Config{AuthBanScope: "sometimes"}
	if err := cfg.Normalize(); err == nil {
		t.Error("invalid auth_ban_scope accepted; a typo would silently change enforcement")
	}
}
