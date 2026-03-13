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

func TestDomainConfig_LimitsTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `
[limits]
max_sends_per_hour = 50
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Limits.MaxSendsPerHour != 50 {
		t.Errorf("expected MaxSendsPerHour 50, got %d", cfg.Limits.MaxSendsPerHour)
	}
}
