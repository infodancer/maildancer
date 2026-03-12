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
