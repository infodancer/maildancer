package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRateLimit_EmptyPath(t *testing.T) {
	cfg, err := LoadRateLimit("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MessagesPerHour != 20 {
		t.Errorf("MessagesPerHour = %d, want 20", cfg.MessagesPerHour)
	}
	if cfg.Burst != 10 {
		t.Errorf("Burst = %d, want 10", cfg.Burst)
	}
}

func TestLoadRateLimit_MissingFile(t *testing.T) {
	cfg, err := LoadRateLimit("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if cfg.MessagesPerHour != 20 {
		t.Errorf("MessagesPerHour = %d, want 20", cfg.MessagesPerHour)
	}
}

func TestLoadRateLimit_NoSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[server]\nhostname = \"mail.example.com\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRateLimit(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MessagesPerHour != 20 {
		t.Errorf("MessagesPerHour = %d, want 20", cfg.MessagesPerHour)
	}
}

func TestLoadRateLimit_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.rate-limit]
messages_per_hour = 50
burst = 15
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRateLimit(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MessagesPerHour != 50 {
		t.Errorf("MessagesPerHour = %d, want 50", cfg.MessagesPerHour)
	}
	if cfg.Burst != 15 {
		t.Errorf("Burst = %d, want 15", cfg.Burst)
	}
}

func TestLoadRateLimit_Unlimited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.rate-limit]
messages_per_hour = 0
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRateLimit(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MessagesPerHour != 0 {
		t.Errorf("MessagesPerHour = %d, want 0 (unlimited)", cfg.MessagesPerHour)
	}
}

func TestLoadRateLimit_PerDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.rate-limit]
messages_per_hour = 20
burst = 10

[queue-manager.rate-limit.domains."gmail.com"]
messages_per_hour = 50
burst = 15

[queue-manager.rate-limit.domains."example.com"]
messages_per_hour = 0
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRateLimit(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Domains) != 2 {
		t.Fatalf("Domains count = %d, want 2", len(cfg.Domains))
	}

	gmail := cfg.Domains["gmail.com"]
	if gmail.MessagesPerHour != 50 {
		t.Errorf("gmail.com MessagesPerHour = %d, want 50", gmail.MessagesPerHour)
	}
	if gmail.Burst != 15 {
		t.Errorf("gmail.com Burst = %d, want 15", gmail.Burst)
	}

	example := cfg.Domains["example.com"]
	if example.MessagesPerHour != 0 {
		t.Errorf("example.com MessagesPerHour = %d, want 0 (unlimited)", example.MessagesPerHour)
	}
}

func TestLoadRateLimit_InlineTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.rate-limit]
messages_per_hour = 20
burst = 10

[queue-manager.rate-limit.domains]
"gmail.com" = { messages_per_hour = 50, burst = 15 }
"example.com" = { messages_per_hour = 0 }
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRateLimit(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Domains) != 2 {
		t.Fatalf("Domains count = %d, want 2", len(cfg.Domains))
	}

	gmail := cfg.Domains["gmail.com"]
	if gmail.MessagesPerHour != 50 || gmail.Burst != 15 {
		t.Errorf("gmail.com = {%d, %d}, want {50, 15}", gmail.MessagesPerHour, gmail.Burst)
	}
}

func TestLoadRateLimit_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("not valid toml [[["), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRateLimit(path)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestLoad_Hostname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager]
hostname = "mail.example.com"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "mail.example.com" {
		t.Errorf("Hostname = %q, want %q", cfg.Hostname, "mail.example.com")
	}
}

func TestLoad_DSNDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DSN.Enabled {
		t.Error("DSN.Enabled should default to true")
	}
	if cfg.DSN.BounceTemplate != "" {
		t.Errorf("DSN.BounceTemplate should default to empty, got %q", cfg.DSN.BounceTemplate)
	}
}

func TestLoad_DSNDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.dsn]
enabled = false
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DSN.Enabled {
		t.Error("DSN.Enabled should be false")
	}
}

func TestLoad_DSNCustomTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.dsn]
bounce_template = "/etc/mail/bounce.tmpl"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DSN.BounceTemplate != "/etc/mail/bounce.tmpl" {
		t.Errorf("DSN.BounceTemplate = %q, want /etc/mail/bounce.tmpl", cfg.DSN.BounceTemplate)
	}
}

func TestLoad_SessionManagerSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager.session-manager]
socket = "/run/session-manager/session-manager.sock"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionManager.Socket != "/run/session-manager/session-manager.sock" {
		t.Errorf("SessionManager.Socket = %q", cfg.SessionManager.Socket)
	}
}

func TestLoad_DomainConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager]
domain_config_path = "/srv/mail/domains"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DomainConfigPath != "/srv/mail/domains" {
		t.Errorf("DomainConfigPath = %q, want /srv/mail/domains", cfg.DomainConfigPath)
	}
}

func TestLoad_DomainConfigPath_Empty(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DomainConfigPath != "" {
		t.Errorf("DomainConfigPath = %q, want empty", cfg.DomainConfigPath)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[queue-manager]
hostname = "mail.example.com"

[queue-manager.rate-limit]
messages_per_hour = 30
burst = 8

[queue-manager.dsn]
enabled = true
bounce_template = "/custom/bounce.tmpl"

[queue-manager.session-manager]
socket = "/run/session-manager/session-manager.sock"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "mail.example.com" {
		t.Errorf("Hostname = %q", cfg.Hostname)
	}
	if cfg.RateLimit.MessagesPerHour != 30 {
		t.Errorf("RateLimit.MessagesPerHour = %d, want 30", cfg.RateLimit.MessagesPerHour)
	}
	if cfg.RateLimit.Burst != 8 {
		t.Errorf("RateLimit.Burst = %d, want 8", cfg.RateLimit.Burst)
	}
	if !cfg.DSN.Enabled {
		t.Error("DSN.Enabled should be true")
	}
	if cfg.DSN.BounceTemplate != "/custom/bounce.tmpl" {
		t.Errorf("DSN.BounceTemplate = %q", cfg.DSN.BounceTemplate)
	}
	if cfg.SessionManager.Socket != "/run/session-manager/session-manager.sock" {
		t.Errorf("SessionManager.Socket = %q", cfg.SessionManager.Socket)
	}
}
