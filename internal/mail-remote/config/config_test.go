package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.SmarthostMaxTransactionsPerConn != 100 {
		t.Errorf("default smarthost max_transactions_per_conn = %d, want 100", cfg.SmarthostMaxTransactionsPerConn)
	}
	if cfg.RemoteMX.MaxTransactionsPerConn != 25 {
		t.Errorf("default remote-mx max_transactions_per_conn = %d, want 25", cfg.RemoteMX.MaxTransactionsPerConn)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SmarthostMaxTransactionsPerConn != 100 {
		t.Errorf("missing file should return defaults, got smarthost max_txn=%d", cfg.SmarthostMaxTransactionsPerConn)
	}
	if cfg.RemoteMX.MaxTransactionsPerConn != 25 {
		t.Errorf("missing file should return defaults, got remote-mx max_txn=%d", cfg.RemoteMX.MaxTransactionsPerConn)
	}
}

func TestLoadFullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[server]
hostname = "mail.example.com"

[mail-remote]
smarthost = "relay.example.com:587"
user = "outbound"
smarthost_max_transactions_per_conn = 200

[mail-remote.remote-mx]
max_transactions_per_conn = 10
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q, want %q", cfg.Hostname, "mail.example.com")
	}
	if cfg.Smarthost != "relay.example.com:587" {
		t.Errorf("smarthost = %q, want %q", cfg.Smarthost, "relay.example.com:587")
	}
	if cfg.User != "outbound" {
		t.Errorf("user = %q, want %q", cfg.User, "outbound")
	}
	if cfg.SmarthostMaxTransactionsPerConn != 200 {
		t.Errorf("smarthost_max_transactions_per_conn = %d, want 200", cfg.SmarthostMaxTransactionsPerConn)
	}
	if cfg.RemoteMX.MaxTransactionsPerConn != 10 {
		t.Errorf("remote-mx.max_transactions_per_conn = %d, want 10", cfg.RemoteMX.MaxTransactionsPerConn)
	}
}

func TestLoadSmarthostOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[mail-remote]
smarthost = "relay.example.com:587"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Smarthost != "relay.example.com:587" {
		t.Errorf("smarthost = %q, want %q", cfg.Smarthost, "relay.example.com:587")
	}
	// remote-mx should keep defaults
	if cfg.RemoteMX.MaxTransactionsPerConn != 25 {
		t.Errorf("remote-mx.max_transactions_per_conn = %d, want 25 (default)", cfg.RemoteMX.MaxTransactionsPerConn)
	}
}

func TestLoadMailRemoteOverridesServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[server]
hostname = "server.example.com"

[mail-remote]
hostname = "outbound.example.com"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Hostname != "outbound.example.com" {
		t.Errorf("hostname = %q, want %q (mail-remote should override server)", cfg.Hostname, "outbound.example.com")
	}
}

func TestLoadServerOnlyHostname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[server]
hostname = "mail.example.com"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q, want %q", cfg.Hostname, "mail.example.com")
	}
	// Defaults preserved for transport-specific settings.
	if cfg.SmarthostMaxTransactionsPerConn != 100 {
		t.Errorf("smarthost_max_transactions_per_conn = %d, want 100", cfg.SmarthostMaxTransactionsPerConn)
	}
	if cfg.RemoteMX.MaxTransactionsPerConn != 25 {
		t.Errorf("remote-mx.max_transactions_per_conn = %d, want 25", cfg.RemoteMX.MaxTransactionsPerConn)
	}
}

func TestApplyEnv(t *testing.T) {
	cfg := Default()
	t.Setenv("MAIL_REMOTE_HOSTNAME", "env.example.com")
	t.Setenv("MAIL_REMOTE_SMARTHOST", "relay.env.com:587")
	t.Setenv("MAIL_REMOTE_SMARTHOST_USER", "envuser")

	cfg = ApplyEnv(cfg)

	if cfg.Hostname != "env.example.com" {
		t.Errorf("hostname = %q, want %q", cfg.Hostname, "env.example.com")
	}
	if cfg.Smarthost != "relay.env.com:587" {
		t.Errorf("smarthost = %q, want %q", cfg.Smarthost, "relay.env.com:587")
	}
	if cfg.User != "envuser" {
		t.Errorf("user = %q, want %q", cfg.User, "envuser")
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("not valid toml [[["), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}
