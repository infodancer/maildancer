package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultValues verifies all default config values are set correctly.
func TestDefaultValues(t *testing.T) {
	cfg := Default()

	if cfg.Hostname != "localhost" {
		t.Errorf("default hostname = %q, want %q", cfg.Hostname, "localhost")
	}

	if cfg.LogLevel != "info" {
		t.Errorf("default log level = %q, want %q", cfg.LogLevel, "info")
	}

	if len(cfg.Listeners) != 1 {
		t.Fatalf("default listeners count = %d, want 1", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Address != ":143" {
		t.Errorf("default listener address = %q, want %q", cfg.Listeners[0].Address, ":143")
	}

	if cfg.Listeners[0].Mode != ModeImap {
		t.Errorf("default listener mode = %q, want %q", cfg.Listeners[0].Mode, ModeImap)
	}

	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("default TLS min version = %q, want %q", cfg.TLS.MinVersion, "1.2")
	}

	if cfg.Timeouts.Connection != "10m" {
		t.Errorf("default connection timeout = %q, want %q", cfg.Timeouts.Connection, "10m")
	}

	if cfg.Timeouts.Command != "1m" {
		t.Errorf("default command timeout = %q, want %q", cfg.Timeouts.Command, "1m")
	}

	if cfg.Timeouts.Idle != "30m" {
		t.Errorf("default idle timeout = %q, want %q", cfg.Timeouts.Idle, "30m")
	}

	if cfg.Limits.MaxConnections != 200 {
		t.Errorf("default max connections = %d, want 200", cfg.Limits.MaxConnections)
	}

	if cfg.Metrics.Enabled {
		t.Error("default metrics enabled = true, want false")
	}

	if cfg.Metrics.Address != ":9102" {
		t.Errorf("default metrics address = %q, want %q", cfg.Metrics.Address, ":9102")
	}

	if cfg.Metrics.Path != "/metrics" {
		t.Errorf("default metrics path = %q, want %q", cfg.Metrics.Path, "/metrics")
	}
}

// TestLoadNonExistentFileReturnsDefaults verifies that a missing config file
// returns the default configuration without error.
func TestLoadNonExistentFileReturnsDefaults(t *testing.T) {
	cfg, err := Load("/tmp/nonexistent-imapd-config-xyz.toml")
	if err != nil {
		t.Fatalf("Load of nonexistent file returned error: %v", err)
	}

	defaults := Default()
	if cfg.Hostname != defaults.Hostname {
		t.Errorf("hostname = %q, want default %q", cfg.Hostname, defaults.Hostname)
	}
	if cfg.Limits.MaxConnections != defaults.Limits.MaxConnections {
		t.Errorf("max connections = %d, want default %d", cfg.Limits.MaxConnections, defaults.Limits.MaxConnections)
	}
}

// TestLoadFromTOML verifies TOML parsing of imapd-specific settings.
func TestLoadFromTOML(t *testing.T) {
	const tomlContent = `
[imapd]
hostname = "mail.example.com"
log_level = "debug"

[[imapd.listeners]]
address = ":993"
mode = "imaps"

[imapd.limits]
max_connections = 500

[imapd.metrics]
enabled = true
address = ":9200"
path = "/prom"
`
	path := writeTempTOML(t, tomlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q, want %q", cfg.Hostname, "mail.example.com")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log level = %q, want %q", cfg.LogLevel, "debug")
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Address != ":993" {
		t.Errorf("listeners = %v, want [{:993 imaps}]", cfg.Listeners)
	}
	if cfg.Listeners[0].Mode != ModeImaps {
		t.Errorf("listener mode = %q, want %q", cfg.Listeners[0].Mode, ModeImaps)
	}
	if cfg.Limits.MaxConnections != 500 {
		t.Errorf("max connections = %d, want 500", cfg.Limits.MaxConnections)
	}
	if !cfg.Metrics.Enabled {
		t.Error("metrics enabled = false, want true")
	}
	if cfg.Metrics.Address != ":9200" {
		t.Errorf("metrics address = %q, want %q", cfg.Metrics.Address, ":9200")
	}
	if cfg.Metrics.Path != "/prom" {
		t.Errorf("metrics path = %q, want %q", cfg.Metrics.Path, "/prom")
	}
}

// TestSharedServerSectionMerged verifies the [server] section merges into imapd config.
func TestSharedServerSectionMerged(t *testing.T) {
	const tomlContent = `
[server]
hostname = "shared.example.com"

[server.tls]
cert_file = "/etc/ssl/cert.pem"
key_file  = "/etc/ssl/key.pem"
`
	path := writeTempTOML(t, tomlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Hostname != "shared.example.com" {
		t.Errorf("hostname = %q, want %q", cfg.Hostname, "shared.example.com")
	}
	if cfg.TLS.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("TLS cert = %q, want %q", cfg.TLS.CertFile, "/etc/ssl/cert.pem")
	}
}

// TestImapSectionOverridesServerSection verifies [imapd] takes precedence over [server].
func TestImapSectionOverridesServerSection(t *testing.T) {
	const tomlContent = `
[server]
hostname = "shared.example.com"

[imapd]
hostname = "imap.example.com"
`
	path := writeTempTOML(t, tomlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Hostname != "imap.example.com" {
		t.Errorf("hostname = %q, want imapd-specific %q", cfg.Hostname, "imap.example.com")
	}
}

// TestApplyFlagsOverridesConfig verifies that flag values override config file values.
func TestApplyFlagsOverridesConfig(t *testing.T) {
	cfg := Default()
	flags := &Flags{
		Hostname:       "flag.example.com",
		LogLevel:       "warn",
		Listen:         ":1430",
		TLSCert:        "/tmp/cert.pem",
		TLSKey:         "/tmp/key.pem",
		MaxConnections: 42,
		DomainsPath:    "/etc/mail/domains",
	}

	result := ApplyFlags(cfg, flags)

	if result.Hostname != "flag.example.com" {
		t.Errorf("hostname = %q, want %q", result.Hostname, "flag.example.com")
	}
	if result.LogLevel != "warn" {
		t.Errorf("log level = %q, want %q", result.LogLevel, "warn")
	}
	if len(result.Listeners) != 1 || result.Listeners[0].Address != ":1430" {
		t.Errorf("listeners = %v, want [{:1430 imap}]", result.Listeners)
	}
	if result.Listeners[0].Mode != ModeImap {
		t.Errorf("listen flag listener mode = %q, want %q", result.Listeners[0].Mode, ModeImap)
	}
	if result.TLS.CertFile != "/tmp/cert.pem" {
		t.Errorf("TLS cert = %q, want %q", result.TLS.CertFile, "/tmp/cert.pem")
	}
	if result.TLS.KeyFile != "/tmp/key.pem" {
		t.Errorf("TLS key = %q, want %q", result.TLS.KeyFile, "/tmp/key.pem")
	}
	if result.Limits.MaxConnections != 42 {
		t.Errorf("max connections = %d, want 42", result.Limits.MaxConnections)
	}
	if result.DomainsPath != "/etc/mail/domains" {
		t.Errorf("domains path = %q, want %q", result.DomainsPath, "/etc/mail/domains")
	}
}

// TestApplyFlagsEmptyFlagsDoNotOverride verifies that zero-value flags leave config unchanged.
func TestApplyFlagsEmptyFlagsDoNotOverride(t *testing.T) {
	cfg := Default()
	cfg.Hostname = "original.example.com"
	cfg.Limits.MaxConnections = 99

	flags := &Flags{} // all zero values

	result := ApplyFlags(cfg, flags)

	if result.Hostname != "original.example.com" {
		t.Errorf("hostname changed to %q, want original %q", result.Hostname, "original.example.com")
	}
	if result.Limits.MaxConnections != 99 {
		t.Errorf("max connections changed to %d, want 99", result.Limits.MaxConnections)
	}
}

// TestListenerModes verifies both valid listener modes are accepted by Validate.
func TestListenerModes(t *testing.T) {
	tests := []struct {
		name    string
		mode    ListenerMode
		wantErr bool
	}{
		{"imap mode", ModeImap, false},
		{"imaps mode", ModeImaps, false},
		{"empty mode", "", true},
		{"invalid mode", "pop3", true},
		{"mixed case invalid", "IMAP", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Listeners = []ListenerConfig{
				{Address: ":143", Mode: tc.mode},
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestValidateRequiresHostname verifies that an empty hostname fails validation.
func TestValidateRequiresHostname(t *testing.T) {
	cfg := Default()
	cfg.Hostname = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty hostname, got nil")
	}
}

// TestValidateRequiresAtLeastOneListener verifies that an empty listener list fails validation.
func TestValidateRequiresAtLeastOneListener(t *testing.T) {
	cfg := Default()
	cfg.Listeners = nil
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for no listeners, got nil")
	}
}

// TestValidateMaxConnectionsMustBePositive verifies that zero or negative max connections fails.
func TestValidateMaxConnectionsMustBePositive(t *testing.T) {
	cfg := Default()
	cfg.Limits.MaxConnections = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for max_connections=0, got nil")
	}
}

// TestValidateInvalidTimeoutStrings verifies that unparseable timeout values fail validation.
func TestValidateInvalidTimeoutStrings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"bad connection timeout", func(c *Config) { c.Timeouts.Connection = "notaduration" }},
		{"bad command timeout", func(c *Config) { c.Timeouts.Command = "notaduration" }},
		{"bad idle timeout", func(c *Config) { c.Timeouts.Idle = "notaduration" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("expected validation error for invalid timeout, got nil")
			}
		})
	}
}

// TestValidateTLSMinVersion verifies valid and invalid TLS version strings.
func TestValidateTLSMinVersion(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{"1.0", false},
		{"1.1", false},
		{"1.2", false},
		{"1.3", false},
		{"1.4", true},
		{"TLS1.2", true},
		{"", false}, // empty is allowed (no override)
	}

	for _, tc := range tests {
		t.Run("version="+tc.version, func(t *testing.T) {
			cfg := Default()
			cfg.TLS.MinVersion = tc.version
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("version %q: expected error, got nil", tc.version)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("version %q: unexpected error: %v", tc.version, err)
			}
		})
	}
}

// TestValidateMetricsRequiresAddressAndPathWhenEnabled verifies that metrics config
// is validated when enabled.
func TestValidateMetricsRequiresAddressAndPathWhenEnabled(t *testing.T) {
	cfg := Default()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when metrics enabled with no address, got nil")
	}

	cfg.Metrics.Address = ":9102"
	cfg.Metrics.Path = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when metrics enabled with no path, got nil")
	}
}

// TestValidateAuthRequiresBackendsWhenTypeSet verifies auth validation logic.
func TestValidateAuthRequiresBackendsWhenTypeSet(t *testing.T) {
	cfg := Default()
	cfg.Auth.Type = "passwd"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when auth type set without credential_backend, got nil")
	}

	cfg.Auth.CredentialBackend = "/etc/mail/passwd"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when auth type set without key_backend, got nil")
	}

	cfg.Auth.KeyBackend = "/etc/mail/keys"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error with all auth fields set, got: %v", err)
	}
}

// TestMinTLSVersionReturns correct crypto/tls constants.
func TestMinTLSVersionReturnsCryptoConstants(t *testing.T) {
	tests := []struct {
		version string
		want    uint16
	}{
		{"1.0", tls.VersionTLS10},
		{"1.1", tls.VersionTLS11},
		{"1.2", tls.VersionTLS12},
		{"1.3", tls.VersionTLS13},
		{"", tls.VersionTLS12},      // default for empty
		{"bogus", tls.VersionTLS12}, // default for invalid
	}

	for _, tc := range tests {
		t.Run("version="+tc.version, func(t *testing.T) {
			tlsCfg := TLSConfig{MinVersion: tc.version}
			got := tlsCfg.MinTLSVersion()
			if got != tc.want {
				t.Errorf("MinTLSVersion(%q) = %d, want %d", tc.version, got, tc.want)
			}
		})
	}
}

// TestTimeoutHelpers verifies the duration accessor methods.
func TestTimeoutHelpers(t *testing.T) {
	t.Run("default connection timeout", func(t *testing.T) {
		tc := TimeoutsConfig{}
		if got := tc.ConnectionTimeout(); got != 10*time.Minute {
			t.Errorf("ConnectionTimeout() = %v, want 10m", got)
		}
	})

	t.Run("default command timeout", func(t *testing.T) {
		tc := TimeoutsConfig{}
		if got := tc.CommandTimeout(); got != 1*time.Minute {
			t.Errorf("CommandTimeout() = %v, want 1m", got)
		}
	})

	t.Run("default idle timeout", func(t *testing.T) {
		tc := TimeoutsConfig{}
		if got := tc.IdleTimeout(); got != 30*time.Minute {
			t.Errorf("IdleTimeout() = %v, want 30m", got)
		}
	})

	t.Run("custom connection timeout", func(t *testing.T) {
		tc := TimeoutsConfig{Connection: "5m"}
		if got := tc.ConnectionTimeout(); got != 5*time.Minute {
			t.Errorf("ConnectionTimeout() = %v, want 5m", got)
		}
	})

	t.Run("invalid falls back to default", func(t *testing.T) {
		tc := TimeoutsConfig{Connection: "notaduration"}
		if got := tc.ConnectionTimeout(); got != 10*time.Minute {
			t.Errorf("ConnectionTimeout() with invalid string = %v, want 10m", got)
		}
	})
}

// TestAuthConfigIsConfigured verifies the IsConfigured helper.
func TestMergeConfigDomainsDataPathAndRspamd(t *testing.T) {
	const tomlContent = `
[imapd]
hostname = "mail.example.com"
domains_path = "/etc/domains"
domains_data_path = "/opt/domains"
mail_session = "/usr/bin/mail-session"

[imapd.rspamd]
controller = "http://rspamd:11334"
junk_folder = "Junk"

[[imapd.listeners]]
address = ":143"
mode = "imap"
`
	path := writeTempTOML(t, tomlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DomainsDataPath != "/opt/domains" {
		t.Errorf("domains_data_path = %q, want %q", cfg.DomainsDataPath, "/opt/domains")
	}
	if cfg.MailSessionCmd != "/usr/bin/mail-session" {
		t.Errorf("mail_session = %q, want %q", cfg.MailSessionCmd, "/usr/bin/mail-session")
	}
	if cfg.Rspamd.Controller != "http://rspamd:11334" {
		t.Errorf("rspamd.controller = %q, want %q", cfg.Rspamd.Controller, "http://rspamd:11334")
	}
	if cfg.Rspamd.JunkFolder != "Junk" {
		t.Errorf("rspamd.junk_folder = %q, want %q", cfg.Rspamd.JunkFolder, "Junk")
	}
}

func TestAuthConfigIsConfigured(t *testing.T) {
	a := AuthConfig{}
	if a.IsConfigured() {
		t.Error("IsConfigured() = true for empty AuthConfig, want false")
	}

	a.Type = "passwd"
	if !a.IsConfigured() {
		t.Error("IsConfigured() = false when type is set, want true")
	}
}

// writeTempTOML writes content to a temp file and returns the path.
// The file is removed when the test ends.
func writeTempTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "imapd.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}
	return path
}
