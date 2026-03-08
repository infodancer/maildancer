// Package deliver orchestrates the full delivery pipeline: forwarding resolution,
// spam checking, sieve parsing, and final maildir write.
package deliver

import (
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config holds the runtime configuration for the delivery pipeline.
type Config struct {
	// DomainsPath is the directory containing per-domain config subdirectories.
	DomainsPath string `toml:"domains_path"`

	// DomainsDataPath is the directory containing per-domain mail data.
	// Defaults to DomainsPath when empty.
	DomainsDataPath string `toml:"domains_data_path"`

	// MaxMessageSize is the maximum message body size in bytes.
	// Defaults to 50 MiB when zero.
	MaxMessageSize int64 `toml:"max_message_size"`

	// DeliveryTimeout is the maximum time allowed for the full delivery pipeline.
	// Defaults to "60s" when empty or unparseable.
	DeliveryTimeout string `toml:"delivery_timeout"`

	// Rspamd holds the global rspamd connection and threshold defaults.
	Rspamd SpamConfig `toml:"rspamd"`
}

// SpamConfig configures the rspamd spam checker.
// Used at global, domain, and user levels — lower levels override higher ones.
type SpamConfig struct {
	// Enabled controls whether spam checking is active. nil means inherit.
	Enabled *bool `toml:"enabled"`

	// URL is the rspamd HTTP endpoint.
	URL string `toml:"url"`

	// Password is the optional rspamd controller password.
	Password string `toml:"password"`

	// Timeout is the HTTP request timeout (e.g. "10s"). Defaults to 10s.
	Timeout string `toml:"timeout"`

	// RejectThreshold is the score at or above which messages are rejected (5xx).
	// nil means use rspamd's action field only.
	RejectThreshold *float64 `toml:"reject_threshold"`

	// TempFailThreshold is the score at or above which messages receive 4xx.
	// nil means disabled.
	TempFailThreshold *float64 `toml:"tempfail_threshold"`

	// FailMode controls behaviour when rspamd is unreachable.
	// Valid values: "open" (accept), "tempfail" (4xx), "reject" (5xx).
	// Defaults to "tempfail".
	FailMode string `toml:"fail_mode"`
}

// DataPath returns the effective data path: DomainsDataPath if set, else DomainsPath.
func (c *Config) DataPath() string {
	if c.DomainsDataPath != "" {
		return c.DomainsDataPath
	}
	return c.DomainsPath
}

// IsEnabled reports whether spam checking is active for this config level.
func (s *SpamConfig) IsEnabled() bool {
	if s.Enabled != nil && !*s.Enabled {
		return false
	}
	return s.URL != ""
}

// GetTimeout returns the configured timeout duration. Defaults to 10 seconds.
func (s *SpamConfig) GetTimeout() time.Duration {
	if s.Timeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// GetFailMode returns the fail mode, defaulting to "tempfail".
func (s *SpamConfig) GetFailMode() string {
	switch s.FailMode {
	case "open", "tempfail", "reject":
		return s.FailMode
	default:
		return "tempfail"
	}
}

// Merge returns a new SpamConfig with non-zero values from override applied
// on top of the receiver. Used to layer user over domain over global config.
func (s SpamConfig) Merge(override SpamConfig) SpamConfig {
	if override.Enabled != nil {
		s.Enabled = override.Enabled
	}
	if override.URL != "" {
		s.URL = override.URL
	}
	if override.Password != "" {
		s.Password = override.Password
	}
	if override.Timeout != "" {
		s.Timeout = override.Timeout
	}
	if override.RejectThreshold != nil {
		s.RejectThreshold = override.RejectThreshold
	}
	if override.TempFailThreshold != nil {
		s.TempFailThreshold = override.TempFailThreshold
	}
	if override.FailMode != "" {
		s.FailMode = override.FailMode
	}
	return s
}

// LoadSpamConfig reads a spam.toml file from path.
// Returns a zero-value SpamConfig and no error if the file does not exist.
func LoadSpamConfig(path string) (SpamConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SpamConfig{}, nil
		}
		return SpamConfig{}, err
	}
	var sc SpamConfig
	if err := toml.Unmarshal(data, &sc); err != nil {
		return SpamConfig{}, err
	}
	return sc, nil
}
