package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainConfig_MaxMessageSizeTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `max_message_size = 2001

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
	if cfg.MaxMessageSize != 2001 {
		t.Errorf("expected MaxMessageSize 2001, got %d", cfg.MaxMessageSize)
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

func TestDomainConfig_DNSTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `
[dns]
hostname = "mail.other-host.example"
public_ip = "192.0.2.25"
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.DNS.Hostname != "mail.other-host.example" {
		t.Errorf("DNS.Hostname = %q", cfg.DNS.Hostname)
	}
	if cfg.DNS.PublicIP != "192.0.2.25" {
		t.Errorf("DNS.PublicIP = %q", cfg.DNS.PublicIP)
	}
}

func TestDomainConfig_EncryptionMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	if err := os.WriteFile(configPath, []byte("encryption_mode = \"on\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.EncryptionMode != EncryptionModeOn {
		t.Errorf("EncryptionMode = %q, want %q", cfg.EncryptionMode, EncryptionModeOn)
	}
	if !cfg.ProvisionKeysByDefault() {
		t.Error("ProvisionKeysByDefault() = false for mode \"on\"")
	}

	// Unset and "off" both mean no default provisioning.
	for _, mode := range []string{"", EncryptionModeOff, "bogus"} {
		c := DomainConfig{EncryptionMode: mode}
		if c.ProvisionKeysByDefault() {
			t.Errorf("ProvisionKeysByDefault() = true for mode %q, want false", mode)
		}
	}
}
