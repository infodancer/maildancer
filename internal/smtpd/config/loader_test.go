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
[smtpd]
hostname = "mail.example.com"
log_level = "debug"

[smtpd.tls]
cert_file = "/etc/ssl/cert.pem"
key_file = "/etc/ssl/key.pem"
min_version = "1.3"

[smtpd.limits]
max_message_size = 10485760
max_recipients = 50

[smtpd.timeouts]
connection = "10m"
command = "2m"

[[smtpd.listeners]]
address = ":25"
mode = "smtp"

[[smtpd.listeners]]
address = ":587"
mode = "submission"
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

	if cfg.Limits.MaxMessageSize != 10485760 {
		t.Errorf("limits.max_message_size = %d, want 10485760", cfg.Limits.MaxMessageSize)
	}

	if cfg.Limits.MaxRecipients != 50 {
		t.Errorf("limits.max_recipients = %d, want 50", cfg.Limits.MaxRecipients)
	}

	if cfg.Timeouts.Connection != "10m" {
		t.Errorf("timeouts.connection = %q, want '10m'", cfg.Timeouts.Connection)
	}

	if cfg.Timeouts.Command != "2m" {
		t.Errorf("timeouts.command = %q, want '2m'", cfg.Timeouts.Command)
	}

	if len(cfg.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Address != ":25" || cfg.Listeners[0].Mode != ModeSmtp {
		t.Errorf("listener[0] = %+v, want address=':25' mode='smtp'", cfg.Listeners[0])
	}

	if cfg.Listeners[1].Address != ":587" || cfg.Listeners[1].Mode != ModeSubmission {
		t.Errorf("listener[1] = %+v, want address=':587' mode='submission'", cfg.Listeners[1])
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	content := `
[smtpd
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
[smtpd]
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

	if cfg.Limits.MaxMessageSize != defaults.Limits.MaxMessageSize {
		t.Errorf("max_message_size = %d, want default %d", cfg.Limits.MaxMessageSize, defaults.Limits.MaxMessageSize)
	}
}

func TestApplyFlags(t *testing.T) {
	cfg := Default()

	flags := &Flags{
		Hostname:       "flag.example.com",
		LogLevel:       "debug",
		TLSCert:        "/flag/cert.pem",
		TLSKey:         "/flag/key.pem",
		MaxMessageSize: 5000000,
		MaxRecipients:  25,
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

	if result.Limits.MaxMessageSize != 5000000 {
		t.Errorf("max_message_size = %d, want 5000000", result.Limits.MaxMessageSize)
	}

	if result.Limits.MaxRecipients != 25 {
		t.Errorf("max_recipients = %d, want 25", result.Limits.MaxRecipients)
	}
}

func TestApplyFlagsEmptyValuesDoNotOverride(t *testing.T) {
	cfg := Default()
	cfg.Hostname = "original.example.com"
	cfg.LogLevel = "warn"
	cfg.Limits.MaxMessageSize = 1000000
	cfg.Limits.MaxRecipients = 50

	// Empty/zero flags should not override
	flags := &Flags{
		Hostname:       "",
		LogLevel:       "",
		MaxMessageSize: 0,
		MaxRecipients:  0,
	}

	result := ApplyFlags(cfg, flags)

	if result.Hostname != "original.example.com" {
		t.Errorf("hostname = %q, want 'original.example.com' (should not be overridden)", result.Hostname)
	}

	if result.LogLevel != "warn" {
		t.Errorf("log_level = %q, want 'warn' (should not be overridden)", result.LogLevel)
	}

	if result.Limits.MaxMessageSize != 1000000 {
		t.Errorf("max_message_size = %d, want 1000000 (should not be overridden)", result.Limits.MaxMessageSize)
	}

	if result.Limits.MaxRecipients != 50 {
		t.Errorf("max_recipients = %d, want 50 (should not be overridden)", result.Limits.MaxRecipients)
	}
}

func TestApplyFlagsListenReplacesAllListeners(t *testing.T) {
	cfg := Default()
	cfg.Listeners = []ListenerConfig{
		{Address: ":25", Mode: ModeSmtp},
		{Address: ":587", Mode: ModeSubmission},
		{Address: ":465", Mode: ModeSmtps},
	}

	flags := &Flags{
		Listen: ":2525",
	}

	result := ApplyFlags(cfg, flags)

	if len(result.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(result.Listeners))
	}

	if result.Listeners[0].Address != ":2525" {
		t.Errorf("listener address = %q, want ':2525'", result.Listeners[0].Address)
	}

	if result.Listeners[0].Mode != ModeSmtp {
		t.Errorf("listener mode = %q, want 'smtp'", result.Listeners[0].Mode)
	}
}

func TestLoadMetricsConfig(t *testing.T) {
	content := `
[smtpd]
hostname = "mail.example.com"

[smtpd.metrics]
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
[smtpd]
hostname = "mail.example.com"

[smtpd.metrics]
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
[smtpd]
hostname = "config.example.com"
log_level = "info"

[smtpd.limits]
max_message_size = 10000000
max_recipients = 100
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Flags should override config file values
	flags := &Flags{
		Hostname:       "flag.example.com",
		MaxMessageSize: 5000000,
	}

	result := ApplyFlags(cfg, flags)

	// Flag values should win
	if result.Hostname != "flag.example.com" {
		t.Errorf("hostname = %q, want 'flag.example.com' (flag should override)", result.Hostname)
	}

	if result.Limits.MaxMessageSize != 5000000 {
		t.Errorf("max_message_size = %d, want 5000000 (flag should override)", result.Limits.MaxMessageSize)
	}

	// Non-overridden config values should remain
	if result.LogLevel != "info" {
		t.Errorf("log_level = %q, want 'info' (config value should remain)", result.LogLevel)
	}

	if result.Limits.MaxRecipients != 100 {
		t.Errorf("max_recipients = %d, want 100 (config value should remain)", result.Limits.MaxRecipients)
	}
}

func TestLoadSharedServerConfig(t *testing.T) {
	content := `
[server]
hostname = "shared.example.com"

[server.delivery]
type = "maildir"
base_path = "/var/mail"

[server.tls]
cert_file = "/etc/ssl/shared-cert.pem"
key_file = "/etc/ssl/shared-key.pem"
min_version = "1.2"

[smtpd]
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

	if cfg.Delivery.Type != "maildir" {
		t.Errorf("delivery.type = %q, want 'maildir'", cfg.Delivery.Type)
	}

	if cfg.Delivery.BasePath != "/var/mail" {
		t.Errorf("delivery.base_path = %q, want '/var/mail'", cfg.Delivery.BasePath)
	}

	if cfg.TLS.CertFile != "/etc/ssl/shared-cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/etc/ssl/shared-cert.pem'", cfg.TLS.CertFile)
	}

	if cfg.TLS.KeyFile != "/etc/ssl/shared-key.pem" {
		t.Errorf("tls.key_file = %q, want '/etc/ssl/shared-key.pem'", cfg.TLS.KeyFile)
	}

	// Smtpd-specific settings should be applied
	if cfg.LogLevel != "warn" {
		t.Errorf("log_level = %q, want 'warn'", cfg.LogLevel)
	}
}

func TestLoadSmtpdOverridesServer(t *testing.T) {
	content := `
[server]
hostname = "shared.example.com"

[server.delivery]
type = "maildir"
base_path = "/var/mail"

[server.tls]
cert_file = "/etc/ssl/shared-cert.pem"
key_file = "/etc/ssl/shared-key.pem"

[smtpd]
hostname = "smtp.example.com"

[smtpd.tls]
cert_file = "/etc/ssl/smtp-cert.pem"

[smtpd.delivery]
type = "maildir"
base_path = "/var/smtpmail"
`

	path := createTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Smtpd values should override server values
	if cfg.Hostname != "smtp.example.com" {
		t.Errorf("hostname = %q, want 'smtp.example.com' (smtpd should override server)", cfg.Hostname)
	}

	if cfg.Delivery.BasePath != "/var/smtpmail" {
		t.Errorf("delivery.base_path = %q, want '/var/smtpmail' (smtpd should override server)", cfg.Delivery.BasePath)
	}

	if cfg.TLS.CertFile != "/etc/ssl/smtp-cert.pem" {
		t.Errorf("tls.cert_file = %q, want '/etc/ssl/smtp-cert.pem' (smtpd should override server)", cfg.TLS.CertFile)
	}

	// Server value should be used when smtpd doesn't override
	if cfg.TLS.KeyFile != "/etc/ssl/shared-key.pem" {
		t.Errorf("tls.key_file = %q, want '/etc/ssl/shared-key.pem' (server value should be inherited)", cfg.TLS.KeyFile)
	}
}

func TestLoadDomainsPath(t *testing.T) {
	// Regression: DomainsPath was missing from mergeConfig so it was silently
	// dropped even when set in [smtpd].domains_path, leaving domainProvider nil.
	tomlContent := `
[smtpd]
hostname = "mail.example.com"
domains_path = "/etc/mail/domains"

[[smtpd.listeners]]
address = ":25"
mode = "smtp"
`
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(tomlContent); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.DomainsPath != "/etc/mail/domains" {
		t.Errorf("DomainsPath = %q, want /etc/mail/domains", cfg.DomainsPath)
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
