package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainConfig_GidTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `gid = 2001

[auth]
type = "passwd"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Gid != 2001 {
		t.Errorf("expected Gid 2001, got %d", cfg.Gid)
	}
}

func TestMergeConfig_RecipientRejection(t *testing.T) {
	base := DomainConfig{RecipientRejection: "rcpt"}
	override := DomainConfig{RecipientRejection: "data"}

	result := mergeConfig(base, override)
	if result.RecipientRejection != "data" {
		t.Errorf("expected merged RecipientRejection %q, got %q", "data", result.RecipientRejection)
	}

	// Empty override should not overwrite base
	result = mergeConfig(base, DomainConfig{})
	if result.RecipientRejection != "rcpt" {
		t.Errorf("expected base RecipientRejection %q retained, got %q", "rcpt", result.RecipientRejection)
	}
}

func TestDomainConfig_OutboundTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `
[outbound]
strategy = "smarthost"
smarthost = "ses.us-east-1.amazonaws.com:587"
smarthost_user = "AKIAEXAMPLE"
password_file = "ses-password"
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Outbound.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost", cfg.Outbound.Strategy)
	}
	if cfg.Outbound.Smarthost != "ses.us-east-1.amazonaws.com:587" {
		t.Errorf("Smarthost = %q", cfg.Outbound.Smarthost)
	}
	if cfg.Outbound.SmarthostUser != "AKIAEXAMPLE" {
		t.Errorf("SmarthostUser = %q", cfg.Outbound.SmarthostUser)
	}
	if cfg.Outbound.PasswordFile != "ses-password" {
		t.Errorf("PasswordFile = %q", cfg.Outbound.PasswordFile)
	}
}

func TestMergeConfig_Outbound(t *testing.T) {
	base := DomainConfig{
		Outbound: OutboundConfig{
			Strategy:      "smarthost",
			Smarthost:     "default-relay:587",
			SmarthostUser: "default-user",
			PasswordFile:  "default-pass",
		},
	}
	override := DomainConfig{
		Outbound: OutboundConfig{
			Smarthost:     "custom-relay:465",
			SmarthostUser: "custom-user",
		},
	}

	result := mergeConfig(base, override)
	if result.Outbound.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost (retained from base)", result.Outbound.Strategy)
	}
	if result.Outbound.Smarthost != "custom-relay:465" {
		t.Errorf("Smarthost = %q, want custom-relay:465", result.Outbound.Smarthost)
	}
	if result.Outbound.SmarthostUser != "custom-user" {
		t.Errorf("SmarthostUser = %q, want custom-user", result.Outbound.SmarthostUser)
	}
	if result.Outbound.PasswordFile != "default-pass" {
		t.Errorf("PasswordFile = %q, want default-pass (retained from base)", result.Outbound.PasswordFile)
	}

	// Empty override should not overwrite base.
	result = mergeConfig(base, DomainConfig{})
	if result.Outbound.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost (retained)", result.Outbound.Strategy)
	}
	if result.Outbound.Smarthost != "default-relay:587" {
		t.Errorf("Smarthost = %q, want default-relay:587 (retained)", result.Outbound.Smarthost)
	}
}

func TestMergeConfig_Gid(t *testing.T) {
	base := DomainConfig{Gid: 1000}
	override := DomainConfig{Gid: 2001}

	result := mergeConfig(base, override)
	if result.Gid != 2001 {
		t.Errorf("expected merged Gid 2001, got %d", result.Gid)
	}

	// Zero override should not overwrite base
	result = mergeConfig(base, DomainConfig{})
	if result.Gid != 1000 {
		t.Errorf("expected base Gid 1000 retained, got %d", result.Gid)
	}
}
