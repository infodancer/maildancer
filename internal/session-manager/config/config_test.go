package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
[session-manager]
socket = "/tmp/session-manager.sock"
domains_path = "/etc/mail/domains"
mail_session_cmd = "/usr/local/bin/mail-session"
idle_timeout = "10m"

[session-manager.auth]
agent_type = "passwd"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Socket != "/tmp/session-manager.sock" {
		t.Errorf("Socket = %q, want %q", cfg.Socket, "/tmp/session-manager.sock")
	}
	if cfg.DomainsPath != "/etc/mail/domains" {
		t.Errorf("DomainsPath = %q, want %q", cfg.DomainsPath, "/etc/mail/domains")
	}
	if cfg.MailSessionCmd != "/usr/local/bin/mail-session" {
		t.Errorf("MailSessionCmd = %q, want %q", cfg.MailSessionCmd, "/usr/local/bin/mail-session")
	}
	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, 10*time.Minute)
	}
	if cfg.Auth.AgentType != "passwd" {
		t.Errorf("Auth.AgentType = %q, want %q", cfg.Auth.AgentType, "passwd")
	}
}

func TestLoad_DefaultIdleTimeout(t *testing.T) {
	content := `
[session-manager]
socket = "/tmp/test.sock"
domains_path = "/etc/mail/domains"
mail_session_cmd = "/usr/local/bin/mail-session"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want default %v", cfg.IdleTimeout, 5*time.Minute)
	}
}

func TestLoad_InvalidIdleTimeout(t *testing.T) {
	content := `
[session-manager]
socket = "/tmp/test.sock"
idle_timeout = "not-a-duration"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid idle_timeout")
	}
}
