package main

import (
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

func TestRunDomainSubcommand_Errors(t *testing.T) {
	p := testPaths(t)
	cases := [][]string{
		{},                         // missing action
		{"create"},                 // missing domain
		{"create", "not_a_domain"}, // invalid name
		{"show", "nosuch.org"},     // missing domain
		{"set", "nosuch.org", "dkim.selector", "x"}, // missing domain
		{"bogus", "example.com"},                    // unknown action
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
