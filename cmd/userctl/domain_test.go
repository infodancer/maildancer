package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/admin"
)

func testPaths(t *testing.T) admin.Paths {
	t.Helper()
	root := t.TempDir()
	p := admin.Paths{
		Config: filepath.Join(root, "config"),
		Data:   filepath.Join(root, "data"),
	}
	if err := os.MkdirAll(p.Config, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Data, 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDomainSubcommand_Lifecycle(t *testing.T) {
	p := testPaths(t)

	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain create: %v", err)
	}
	if !p.DomainExists("example.com") {
		t.Fatal("domain not created")
	}

	// list and show run clean.
	if err := runDomainSubcommand([]string{"list"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain list: %v", err)
	}
	if err := runDomainSubcommand([]string{"show", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain show: %v", err)
	}

	// set + unset a config key.
	if err := runDomainSubcommand([]string{"set", "example.com", "recipient_rejection", "data"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain set: %v", err)
	}
	v, err := p.GetDomainConfigValue("example.com", "recipient_rejection")
	if err != nil || v != "\"data\"" {
		t.Fatalf("config value = %q, %v", v, err)
	}
	if err := runDomainSubcommand([]string{"set", "example.com", "recipient_rejection"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain unset: %v", err)
	}
	v, _ = p.GetDomainConfigValue("example.com", "recipient_rejection")
	if v != "" {
		t.Fatalf("config value after unset = %q", v)
	}

	// domain key lifecycle via --password-stdin.
	if err := runDomainSubcommand([]string{"key", "create", "example.com", "--password-stdin"}, p, strings.NewReader("keypassword\n")); err != nil {
		t.Fatalf("domain key create: %v", err)
	}
	status, err := p.DomainKeyStatus("example.com")
	if err != nil || !status.Exists {
		t.Fatalf("domain key missing: %+v, %v", status, err)
	}
	if err := runDomainSubcommand([]string{"key", "show", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain key show: %v", err)
	}
	if err := runDomainSubcommand([]string{"key", "del", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain key del: %v", err)
	}

	// delete.
	if err := runDomainSubcommand([]string{"del", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain del: %v", err)
	}
	if p.DomainExists("example.com") {
		t.Fatal("domain still exists after del")
	}
}

func TestRunDomainSubcommand_DelForce(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runUserSubcommand([]string{"add", "alice@example.com", "--password-stdin"}, p, strings.NewReader("password123\n")); err != nil {
		t.Fatal(err)
	}

	// Refuses without --force.
	if err := runDomainSubcommand([]string{"del", "example.com"}, p, strings.NewReader("")); err == nil {
		t.Fatal("del with users succeeded without --force")
	}
	if err := runDomainSubcommand([]string{"del", "example.com", "--force"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("del --force: %v", err)
	}
}

// TestRunDomainSubcommand_Check: `domain check` reports clean (nil error,
// exit 0 via exitOnErr) on a fixed domain, errors (exit 1) when a config file
// mode has drifted, and is clean again after `domain fix` repairs it.
func TestRunDomainSubcommand_Check(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain create: %v", err)
	}
	if err := runDomainSubcommand([]string{"fix", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain fix: %v", err)
	}

	if err := runDomainSubcommand([]string{"check", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain check on a fixed domain: %v", err)
	}

	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chmod(configToml, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := runDomainSubcommand([]string{"check", "example.com"}, p, strings.NewReader("")); err == nil {
		t.Fatal("domain check with drifted config.toml succeeded, want error (exit 1)")
	}

	// Check must not have repaired it.
	info, err := os.Stat(configToml)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("domain check repaired the mode: %v", info.Mode())
	}

	if err := runDomainSubcommand([]string{"fix", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain fix (repair): %v", err)
	}
	if err := runDomainSubcommand([]string{"check", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Errorf("domain check after repair: %v", err)
	}
}

func TestRunDomainSubcommand_Errors(t *testing.T) {
	p := testPaths(t)
	cases := [][]string{
		{},                         // missing action
		{"create"},                 // missing domain
		{"create", "not_a_domain"}, // invalid name
		{"show", "nosuch.org"},     // missing domain
		{"set", "nosuch.org", "dkim.selector", "x"}, // missing domain
		{"check"},                // missing domain argument
		{"check", "nosuch.org"},  // missing domain
		{"bogus", "example.com"}, // unknown action
	}
	for _, args := range cases {
		if err := runDomainSubcommand(args, p, strings.NewReader("")); err == nil {
			t.Errorf("runDomainSubcommand(%v) succeeded, want error", args)
		}
	}
}

func TestRunDomainSubcommand_DKIM(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain create: %v", err)
	}

	// show before create reports not configured (an error).
	if err := runDomainSubcommand([]string{"dkim", "show", "example.com"}, p, strings.NewReader("")); err == nil {
		t.Error("dkim show before create succeeded, want error")
	}

	if err := runDomainSubcommand([]string{"dkim", "create", "example.com", "--selector", "sel1"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("dkim create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Config, "example.com", "dkim", "sel1.key")); err != nil {
		t.Errorf("expected key file: %v", err)
	}

	// Re-create without --force is refused; with --force succeeds.
	if err := runDomainSubcommand([]string{"dkim", "create", "example.com", "--selector", "sel1"}, p, strings.NewReader("")); err == nil {
		t.Error("dkim create over existing key succeeded, want error")
	}
	if err := runDomainSubcommand([]string{"dkim", "create", "example.com", "--selector", "sel1", "--force"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dkim create --force: %v", err)
	}

	if err := runDomainSubcommand([]string{"dkim", "show", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dkim show: %v", err)
	}

	// Default selector (no --selector flag) works too.
	if err := runDomainSubcommand([]string{"dkim", "create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dkim create with default selector: %v", err)
	}
}

func TestRunDomainSubcommand_DKIMUsageErrors(t *testing.T) {
	p := testPaths(t)
	for _, args := range [][]string{
		{"dkim"},
		{"dkim", "create"},
		{"dkim", "show"},
		{"dkim", "frobnicate", "example.com"},
		{"dkim", "create", "example.com", "--selector"},
		{"dkim", "create", "a.com", "b.com"},
	} {
		if err := runDomainSubcommand(args, p, strings.NewReader("")); err == nil {
			t.Errorf("runDomainSubcommand(%v) succeeded, want error", args)
		}
	}
}

// dnsTestResolver returns a fake where example.com is fully configured for
// mail.example.net / 192.0.2.25 (minus DKIM, unless a key is created).
func dnsTestResolver() *fakeResolver {
	return &fakeResolver{
		hosts: map[string][]string{
			"example.com":      {"192.0.2.25"},
			"mail.example.net": {"192.0.2.25"},
		},
		mxs: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.net.", Pref: 10}},
		},
		txts: map[string][]string{
			"example.com":        {"v=spf1 ip4:192.0.2.25 -all"},
			"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
		},
		ptrs: map[string][]string{
			"192.0.2.25": {"mail.example.net."},
		},
	}
}

func TestRunDomainSubcommand_DNS(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("domain create: %v", err)
	}

	old := dnsResolver
	dnsResolver = dnsTestResolver()
	defer func() { dnsResolver = old }()

	// No hostname from any source: refused with guidance.
	if err := runDomainSubcommand([]string{"dns", "example.com"}, p, strings.NewReader("")); err == nil {
		t.Error("dns without hostname succeeded, want error")
	}

	// Explicit flags: passes (DKIM unconfigured is only a warning).
	if err := runDomainSubcommand([]string{"dns", "example.com", "--hostname", "mail.example.net", "--ip", "192.0.2.25"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dns with flags: %v", err)
	}

	// Hostname only: IP derived from the hostname's A record.
	if err := runDomainSubcommand([]string{"dns", "example.com", "--hostname", "mail.example.net"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dns with derived IP: %v", err)
	}

	// Sourcing from per-domain config, no flags at all.
	if err := runDomainSubcommand([]string{"set", "example.com", "dns.hostname", "mail.example.net"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runDomainSubcommand([]string{"set", "example.com", "dns.public_ip", "192.0.2.25"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runDomainSubcommand([]string{"dns", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Errorf("dns from domain config: %v", err)
	}
}

func TestRunDomainSubcommand_DNSFailures(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}

	old := dnsResolver
	dnsResolver = &fakeResolver{} // empty zone: everything fails
	defer func() { dnsResolver = old }()

	// Failed checks surface as a non-nil error so scripts can gate on it.
	err := runDomainSubcommand([]string{"dns", "example.com", "--hostname", "mail.example.net", "--ip", "192.0.2.25"}, p, strings.NewReader(""))
	if err == nil {
		t.Error("dns with empty zone succeeded, want error")
	}
}
