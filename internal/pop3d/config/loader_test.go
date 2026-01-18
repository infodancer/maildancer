package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}

	// Should return defaults
	expected := Default()
	if cfg.Hostname != expected.Hostname {
		t.Errorf("expected hostname %q, got %q", expected.Hostname, cfg.Hostname)
	}
}

func TestLoadValidTOML(t *testing.T) {
	content := `
[pop3d]
hostname = "mail.example.com"
log_level = "debug"

[pop3d.tls]
cert_file = "/etc/ssl/cert.pem"
key_file = "/etc/ssl/key.pem"
min_version = "1.3"

[pop3d.limits]
max_connections = 50

[pop3d.timeouts]
connection = "15m"
idle = "10m"

[[pop3d.listeners]]
address = ":110"
mode = "pop3"

[[pop3d.listeners]]
address = ":995"
mode = "pop3s"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q, want 'mail.example.com'", cfg.Hostname)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("log_level = %q, want 'debug'", cfg.LogLevel)
	}

	if cfg.TLS.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/etc/ssl/cert.pem'", cfg.TLS.CertFile)
	}

	if cfg.TLS.KeyFile != "/etc/ssl/key.pem" {
		t.Errorf("tls.key_file = %q, want '/etc/ssl/key.pem'", cfg.TLS.KeyFile)
	}

	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("tls.min_version = %q, want '1.3'", cfg.TLS.MinVersion)
	}

	if cfg.Limits.MaxConnections != 50 {
		t.Errorf("limits.max_connections = %d, want 50", cfg.Limits.MaxConnections)
	}

	if cfg.Timeouts.Connection != "15m" {
		t.Errorf("timeouts.connection = %q, want '15m'", cfg.Timeouts.Connection)
	}

	if cfg.Timeouts.Idle != "10m" {
		t.Errorf("timeouts.idle = %q, want '10m'", cfg.Timeouts.Idle)
	}

	if len(cfg.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Address != ":110" || cfg.Listeners[0].Mode != ModePop3 {
		t.Errorf("listener[0] = %+v, want address=':110' mode='pop3'", cfg.Listeners[0])
	}

	if cfg.Listeners[1].Address != ":995" || cfg.Listeners[1].Mode != ModePop3s {
		t.Errorf("listener[1] = %+v, want address=':995' mode='pop3s'", cfg.Listeners[1])
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	content := `
[pop3d
hostname = "broken
`

	path := createTempConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}

func TestLoadPartialConfig(t *testing.T) {
	content := `
[pop3d]
hostname = "partial.example.com"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Provided value should be used
	if cfg.Hostname != "partial.example.com" {
		t.Errorf("hostname = %q, want 'partial.example.com'", cfg.Hostname)
	}

	// Defaults should be preserved for unspecified values
	defaults := Default()
	if cfg.LogLevel != defaults.LogLevel {
		t.Errorf("log_level = %q, want default %q", cfg.LogLevel, defaults.LogLevel)
	}

	if cfg.Limits.MaxConnections != defaults.Limits.MaxConnections {
		t.Errorf("max_connections = %d, want default %d", cfg.Limits.MaxConnections, defaults.Limits.MaxConnections)
	}
}

func TestApplyFlags(t *testing.T) {
	cfg := Default()

	flags := &Flags{
		Hostname:       "flag.example.com",
		LogLevel:       "debug",
		TLSCert:        "/flag/cert.pem",
		TLSKey:         "/flag/key.pem",
		MaxConnections: 25,
	}

	result := ApplyFlags(cfg, flags)

	if result.Hostname != "flag.example.com" {
		t.Errorf("hostname = %q, want 'flag.example.com'", result.Hostname)
	}

	if result.LogLevel != "debug" {
		t.Errorf("log_level = %q, want 'debug'", result.LogLevel)
	}

	if result.TLS.CertFile != "/flag/cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/flag/cert.pem'", result.TLS.CertFile)
	}

	if result.TLS.KeyFile != "/flag/key.pem" {
		t.Errorf("tls.key_file = %q, want '/flag/key.pem'", result.TLS.KeyFile)
	}

	if result.Limits.MaxConnections != 25 {
		t.Errorf("max_connections = %d, want 25", result.Limits.MaxConnections)
	}
}

func TestApplyFlagsEmptyValuesDoNotOverride(t *testing.T) {
	cfg := Default()
	cfg.Hostname = "original.example.com"
	cfg.LogLevel = "warn"
	cfg.Limits.MaxConnections = 50

	// Empty/zero flags should not override
	flags := &Flags{
		Hostname:       "",
		LogLevel:       "",
		MaxConnections: 0,
	}

	result := ApplyFlags(cfg, flags)

	if result.Hostname != "original.example.com" {
		t.Errorf("hostname = %q, want 'original.example.com' (should not be overridden)", result.Hostname)
	}

	if result.LogLevel != "warn" {
		t.Errorf("log_level = %q, want 'warn' (should not be overridden)", result.LogLevel)
	}

	if result.Limits.MaxConnections != 50 {
		t.Errorf("max_connections = %d, want 50 (should not be overridden)", result.Limits.MaxConnections)
	}
}

func TestApplyFlagsListenReplacesAllListeners(t *testing.T) {
	cfg := Default()
	cfg.Listeners = []ListenerConfig{
		{Address: ":110", Mode: ModePop3},
		{Address: ":995", Mode: ModePop3s},
	}

	flags := &Flags{
		Listen: ":1110",
	}

	result := ApplyFlags(cfg, flags)

	if len(result.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(result.Listeners))
	}

	if result.Listeners[0].Address != ":1110" {
		t.Errorf("listener address = %q, want ':1110'", result.Listeners[0].Address)
	}

	if result.Listeners[0].Mode != ModePop3 {
		t.Errorf("listener mode = %q, want 'pop3'", result.Listeners[0].Mode)
	}
}

func TestFlagPriorityOverConfig(t *testing.T) {
	content := `
[pop3d]
hostname = "config.example.com"
log_level = "info"

[pop3d.limits]
max_connections = 100
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Flags should override config file values
	flags := &Flags{
		Hostname:       "flag.example.com",
		MaxConnections: 50,
	}

	result := ApplyFlags(cfg, flags)

	// Flag values should win
	if result.Hostname != "flag.example.com" {
		t.Errorf("hostname = %q, want 'flag.example.com' (flag should override)", result.Hostname)
	}

	if result.Limits.MaxConnections != 50 {
		t.Errorf("max_connections = %d, want 50 (flag should override)", result.Limits.MaxConnections)
	}

	// Non-overridden config values should remain
	if result.LogLevel != "info" {
		t.Errorf("log_level = %q, want 'info' (config value should remain)", result.LogLevel)
	}
}

func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	return path
}
