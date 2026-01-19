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
command = "2m"
idle = "45m"

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

	if cfg.Timeouts.Command != "2m" {
		t.Errorf("timeouts.command = %q, want '2m'", cfg.Timeouts.Command)
	}

	if cfg.Timeouts.Idle != "45m" {
		t.Errorf("timeouts.idle = %q, want '45m'", cfg.Timeouts.Idle)
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

func TestLoadSharedServerConfig(t *testing.T) {
	content := `
[server]
hostname = "shared.example.com"
maildir = "/var/mail"

[server.tls]
cert_file = "/etc/ssl/shared-cert.pem"
key_file = "/etc/ssl/shared-key.pem"
min_version = "1.2"

[pop3d]
log_level = "warn"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Server settings should be inherited
	if cfg.Hostname != "shared.example.com" {
		t.Errorf("hostname = %q, want 'shared.example.com'", cfg.Hostname)
	}

	if cfg.Maildir != "/var/mail" {
		t.Errorf("maildir = %q, want '/var/mail'", cfg.Maildir)
	}

	if cfg.TLS.CertFile != "/etc/ssl/shared-cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/etc/ssl/shared-cert.pem'", cfg.TLS.CertFile)
	}

	if cfg.TLS.KeyFile != "/etc/ssl/shared-key.pem" {
		t.Errorf("tls.key_file = %q, want '/etc/ssl/shared-key.pem'", cfg.TLS.KeyFile)
	}

	// Pop3d-specific settings should be applied
	if cfg.LogLevel != "warn" {
		t.Errorf("log_level = %q, want 'warn'", cfg.LogLevel)
	}
}

func TestLoadPop3dOverridesServer(t *testing.T) {
	content := `
[server]
hostname = "shared.example.com"
maildir = "/var/mail"

[server.tls]
cert_file = "/etc/ssl/shared-cert.pem"
key_file = "/etc/ssl/shared-key.pem"

[pop3d]
hostname = "pop3.example.com"
maildir = "/var/pop3mail"

[pop3d.tls]
cert_file = "/etc/ssl/pop3-cert.pem"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Pop3d values should override server values
	if cfg.Hostname != "pop3.example.com" {
		t.Errorf("hostname = %q, want 'pop3.example.com' (pop3d should override server)", cfg.Hostname)
	}

	if cfg.Maildir != "/var/pop3mail" {
		t.Errorf("maildir = %q, want '/var/pop3mail' (pop3d should override server)", cfg.Maildir)
	}

	if cfg.TLS.CertFile != "/etc/ssl/pop3-cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/etc/ssl/pop3-cert.pem' (pop3d should override server)", cfg.TLS.CertFile)
	}

	// Server value should be used when pop3d doesn't override
	if cfg.TLS.KeyFile != "/etc/ssl/shared-key.pem" {
		t.Errorf("tls.key_file = %q, want '/etc/ssl/shared-key.pem' (server value should be inherited)", cfg.TLS.KeyFile)
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
		Maildir:        "/flag/maildir",
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

	if result.Maildir != "/flag/maildir" {
		t.Errorf("maildir = %q, want '/flag/maildir'", result.Maildir)
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
		Listen: ":1100",
	}

	result := ApplyFlags(cfg, flags)

	if len(result.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(result.Listeners))
	}

	if result.Listeners[0].Address != ":1100" {
		t.Errorf("listener address = %q, want ':1100'", result.Listeners[0].Address)
	}

	if result.Listeners[0].Mode != ModePop3 {
		t.Errorf("listener mode = %q, want 'pop3'", result.Listeners[0].Mode)
	}
}

func TestLoadMetricsConfig(t *testing.T) {
	content := `
[pop3d]
hostname = "mail.example.com"

[pop3d.metrics]
enabled = true
address = ":9200"
path = "/custom-metrics"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Metrics.Enabled {
		t.Errorf("metrics.enabled = %v, want true", cfg.Metrics.Enabled)
	}

	if cfg.Metrics.Address != ":9200" {
		t.Errorf("metrics.address = %q, want ':9200'", cfg.Metrics.Address)
	}

	if cfg.Metrics.Path != "/custom-metrics" {
		t.Errorf("metrics.path = %q, want '/custom-metrics'", cfg.Metrics.Path)
	}
}

func TestLoadMetricsConfigPartial(t *testing.T) {
	content := `
[pop3d]
hostname = "mail.example.com"

[pop3d.metrics]
enabled = true
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// enabled should be set from file
	if !cfg.Metrics.Enabled {
		t.Errorf("metrics.enabled = %v, want true", cfg.Metrics.Enabled)
	}

	// address and path should use defaults
	defaults := Default()
	if cfg.Metrics.Address != defaults.Metrics.Address {
		t.Errorf("metrics.address = %q, want default %q", cfg.Metrics.Address, defaults.Metrics.Address)
	}

	if cfg.Metrics.Path != defaults.Metrics.Path {
		t.Errorf("metrics.path = %q, want default %q", cfg.Metrics.Path, defaults.Metrics.Path)
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
