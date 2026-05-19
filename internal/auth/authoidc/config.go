package authoidc

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level auth-oidc configuration.
type Config struct {
	Server  ServerConfig   `toml:"server"`
	Clients []ClientConfig `toml:"client"`
}

// ServerConfig holds server-level settings.
//
// Signing-key knobs (per docs/signing-key-rotation.md):
//   - DefaultSigningAlgorithm picks the algorithm for newly generated keys
//     (first-time generation and scheduled rotations). Existing keys keep
//     their own algorithm. Validated at startup; unknown values fail with
//     a clear error rather than silently falling back.
//   - KeyRotationInterval, KeyRetentionAfterRetire, and
//     KeyRotationCheckInterval are duration strings parsed by
//     time.ParseDuration. Empty/zero values fall back to defaults.
type ServerConfig struct {
	Listen         string `toml:"listen"`
	DataDir        string `toml:"data_dir"`
	DomainDataPath string `toml:"domain_data_path"`
	JWTTTLSec      int64  `toml:"jwt_ttl_sec"`
	SessionTTLSec  int64  `toml:"session_ttl_sec"`

	DefaultSigningAlgorithm  string `toml:"default_signing_algorithm"`
	KeyRotationInterval      string `toml:"key_rotation_interval"`
	KeyRetentionAfterRetire  string `toml:"key_retention_after_retire"`
	KeyRotationCheckInterval string `toml:"key_rotation_check_interval"`
}

// supportedSigningAlgorithms lists the JWA algorithm strings auth-oidc can
// generate and sign with. Add to keys.go's generatePrivateKey / algForKey /
// jwaAlgorithm switches in lockstep.
var supportedSigningAlgorithms = map[string]struct{}{
	AlgRS256: {},
	AlgES256: {},
	AlgEdDSA: {},
}

// ClientConfig describes a registered OIDC relying party.
// Secret is empty for public clients (PKCE only).
type ClientConfig struct {
	Domain       string   `toml:"domain"`
	ID           string   `toml:"id"`
	Secret       string   `toml:"secret"`
	RedirectURIs []string `toml:"redirect_uris"`
}

// Load reads and parses a TOML config file, applying defaults for omitted fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Server.JWTTTLSec == 0 {
		cfg.Server.JWTTTLSec = 3600 // 1 hour
	}
	if cfg.Server.SessionTTLSec == 0 {
		cfg.Server.SessionTTLSec = 604800 // 7 days
	}

	if cfg.Server.DefaultSigningAlgorithm == "" {
		cfg.Server.DefaultSigningAlgorithm = AlgES256
	}
	if _, ok := supportedSigningAlgorithms[cfg.Server.DefaultSigningAlgorithm]; !ok {
		return nil, fmt.Errorf("unsupported default_signing_algorithm: %q (supported: RS256, ES256, EdDSA)",
			cfg.Server.DefaultSigningAlgorithm)
	}

	for _, f := range []struct {
		name string
		val  string
	}{
		{"key_rotation_interval", cfg.Server.KeyRotationInterval},
		{"key_retention_after_retire", cfg.Server.KeyRetentionAfterRetire},
		{"key_rotation_check_interval", cfg.Server.KeyRotationCheckInterval},
	} {
		if f.val == "" {
			continue
		}
		if _, err := time.ParseDuration(f.val); err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", f.name, f.val, err)
		}
	}

	return &cfg, nil
}

// keyRotationInterval returns the configured rotation interval or the
// default when unset/empty. Parser errors are caught at Load time, so
// time.ParseDuration here is just decoding.
func (c *ServerConfig) keyRotationInterval() time.Duration {
	if d, ok := parseDurationOrZero(c.KeyRotationInterval); ok {
		return d
	}
	return defaultKeyRotationInterval
}

func (c *ServerConfig) keyRetentionAfterRetire() time.Duration {
	if d, ok := parseDurationOrZero(c.KeyRetentionAfterRetire); ok {
		return d
	}
	return defaultKeyRetentionAfterRetire
}

func (c *ServerConfig) keyRotationCheckInterval() time.Duration {
	if d, ok := parseDurationOrZero(c.KeyRotationCheckInterval); ok {
		return d
	}
	return defaultKeyRotationCheckInterval
}

// parseDurationOrZero parses a duration string. Empty input and parse
// errors both return (0, false). Parse errors should already have been
// caught by Load; this helper is a belt-and-braces fallback for callers
// that may receive a struct that didn't go through Load.
func parseDurationOrZero(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}
