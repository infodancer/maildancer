package authoidc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoad_SigningKeyDefaults confirms that an empty config loads with the
// documented defaults: ES256 algorithm, 90d rotation interval, 24h retire
// retention, 24h check interval.
func TestLoad_SigningKeyDefaults(t *testing.T) {
	cfg := writeConfig(t, ``)
	if cfg.Server.DefaultSigningAlgorithm != AlgES256 {
		t.Errorf("default_signing_algorithm = %q, want ES256", cfg.Server.DefaultSigningAlgorithm)
	}
	if got := cfg.Server.keyRotationInterval(); got != 90*24*time.Hour {
		t.Errorf("rotation interval = %v, want 90d", got)
	}
	if got := cfg.Server.keyRetentionAfterRetire(); got != 24*time.Hour {
		t.Errorf("retention = %v, want 24h", got)
	}
	if got := cfg.Server.keyRotationCheckInterval(); got != 24*time.Hour {
		t.Errorf("check interval = %v, want 24h", got)
	}
}

func TestLoad_SigningKeyOverrides(t *testing.T) {
	cfg := writeConfig(t, `
[server]
default_signing_algorithm = "EdDSA"
key_rotation_interval = "720h"
key_retention_after_retire = "48h"
key_rotation_check_interval = "1h"
`)
	if cfg.Server.DefaultSigningAlgorithm != AlgEdDSA {
		t.Errorf("alg = %q, want EdDSA", cfg.Server.DefaultSigningAlgorithm)
	}
	if got := cfg.Server.keyRotationInterval(); got != 720*time.Hour {
		t.Errorf("rotation interval = %v, want 720h", got)
	}
	if got := cfg.Server.keyRetentionAfterRetire(); got != 48*time.Hour {
		t.Errorf("retention = %v, want 48h", got)
	}
	if got := cfg.Server.keyRotationCheckInterval(); got != time.Hour {
		t.Errorf("check interval = %v, want 1h", got)
	}
}

func TestLoad_RejectsUnknownAlgorithm(t *testing.T) {
	_, err := loadConfigString(t, `
[server]
default_signing_algorithm = "HS256"
`)
	if err == nil || !strings.Contains(err.Error(), "unsupported default_signing_algorithm") {
		t.Errorf("err = %v, want unsupported_signing_algorithm error", err)
	}
}

func TestLoad_RejectsInvalidDuration(t *testing.T) {
	_, err := loadConfigString(t, `
[server]
key_rotation_interval = "yes please"
`)
	if err == nil || !strings.Contains(err.Error(), "key_rotation_interval") {
		t.Errorf("err = %v, want key_rotation_interval error", err)
	}
}

// writeConfig writes raw to a temp file and returns the parsed Config. Fails
// the test if Load returns an error.
func writeConfig(t *testing.T, raw string) *Config {
	t.Helper()
	cfg, err := loadConfigString(t, raw)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func loadConfigString(t *testing.T, raw string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return Load(path)
}
