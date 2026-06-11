package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/auth/domain"
)

func TestSetDomainConfig(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	// Set values across sectioned, top-level, enum, and int kinds.
	sets := [][3]string{
		{"example.com", "outbound.strategy", "smarthost"},
		{"example.com", "outbound.smarthost", "relay.example.net:587"},
		{"example.com", "limits.max_sends_per_hour", "200"},
		{"example.com", "max_message_size", "10485760"},
		{"example.com", "recipient_rejection", "data"},
		{"example.com", "dkim.selector", "sel1"},
	}
	for _, s := range sets {
		if err := p.SetDomainConfig(s[0], s[1], s[2]); err != nil {
			t.Fatalf("SetDomainConfig(%s=%s): %v", s[1], s[2], err)
		}
	}

	// The resulting file parses as a DomainConfig with the right values,
	// and the creation-time defaults survived the edits.
	cfg, err := domain.LoadDomainConfig(filepath.Join(p.Config, "example.com", "config.toml"))
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Outbound.Strategy != "smarthost" || cfg.Outbound.Smarthost != "relay.example.net:587" {
		t.Errorf("outbound = %+v", cfg.Outbound)
	}
	if cfg.Limits.MaxSendsPerHour != 200 {
		t.Errorf("max_sends_per_hour = %d", cfg.Limits.MaxSendsPerHour)
	}
	if cfg.MaxMessageSize != 10485760 {
		t.Errorf("max_message_size = %d", cfg.MaxMessageSize)
	}
	if cfg.RecipientRejection != "data" {
		t.Errorf("recipient_rejection = %q", cfg.RecipientRejection)
	}
	if cfg.DKIM.Selector != "sel1" {
		t.Errorf("dkim.selector = %q", cfg.DKIM.Selector)
	}
	if cfg.Auth.Type != "passwd" || cfg.MsgStore.Type != "maildir" {
		t.Errorf("creation defaults lost: auth=%+v msgstore=%+v", cfg.Auth, cfg.MsgStore)
	}

	// Read back a raw value.
	v, err := p.GetDomainConfigValue("example.com", "outbound.strategy")
	if err != nil || v != "\"smarthost\"" {
		t.Errorf("GetDomainConfigValue = %q, %v", v, err)
	}

	// Empty value removes the key.
	if err := p.SetDomainConfig("example.com", "recipient_rejection", ""); err != nil {
		t.Fatalf("unset: %v", err)
	}
	v, _ = p.GetDomainConfigValue("example.com", "recipient_rejection")
	if v != "" {
		t.Errorf("value after unset = %q", v)
	}
}

func TestSetDomainConfig_Validation(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		key, value string
	}{
		{"forwards", "x"},                       // not in whitelist
		{"gid", "1234"},                         // not in whitelist
		{"outbound.strategy", "carrier-pigeon"}, // bad enum
		{"recipient_rejection", "never"},        // bad enum
		{"max_message_size", "-5"},              // negative int
		{"limits.max_sends_per_hour", "lots"},   // non-int
		{"msgstore.base_path", "../../etc"},     // traversal
	}
	for _, c := range cases {
		if err := p.SetDomainConfig("example.com", c.key, c.value); err == nil {
			t.Errorf("SetDomainConfig(%s=%s) succeeded, want error", c.key, c.value)
		}
	}

	if err := p.SetDomainConfig("nosuch.org", "dkim.selector", "x"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("missing domain err = %v", err)
	}
}

func TestSetDomainConfig_PreservesComments(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(p.Config, "example.com", "config.toml")
	content := "# operator notes: do not touch\n[auth]\ntype = \"passwd\" # inline\n\n[custom]\nfoo = \"bar\"\n"
	if err := os.WriteFile(configPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := p.SetDomainConfig("example.com", "dkim.selector", "sel1"); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# operator notes: do not touch", "[custom]", "foo = \"bar\"", "[dkim]", "selector = \"sel1\""} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
