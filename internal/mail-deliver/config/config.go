// Package config provides configuration types and loading for mail-deliver.
package config

import "time"

// Config holds the runtime configuration for mail-deliver.
// It is populated from the [maildeliver] section of the shared TOML config file.
type Config struct {
	// DomainsPath is the directory containing per-domain config subdirectories
	// (config.toml, passwd, keys, forwards, user_forwards/).
	DomainsPath string `toml:"domains_path"`

	// DomainsDataPath is the directory containing per-domain mail data
	// (users/{localpart}/Maildir, users/{localpart}/spam.toml, etc.).
	// Defaults to DomainsPath when empty.
	DomainsDataPath string `toml:"domains_data_path"`

	// MaxMessageSize is the maximum message body size in bytes.
	// Messages exceeding this limit are rejected with a permanent failure.
	// Defaults to 52428800 (50 MiB) when zero.
	MaxMessageSize int64 `toml:"max_message_size"`

	// DeliveryTimeout is the maximum time allowed for the full delivery pipeline.
	// Defaults to "60s" when empty or unparseable.
	DeliveryTimeout string `toml:"delivery_timeout"`

	// Rspamd holds the global rspamd connection and threshold defaults.
	// Per-domain and per-user spam.toml files override these values.
	Rspamd SpamConfig `toml:"rspamd"`
}

// SpamConfig configures the rspamd spam checker.
// Used at global, domain, and user levels — lower levels override higher ones.
type SpamConfig struct {
	// Enabled controls whether spam checking is active. nil means inherit.
	Enabled *bool `toml:"enabled"`

	// URL is the rspamd HTTP endpoint (e.g. "http://localhost:11333").
	URL string `toml:"url"`

	// Password is the optional rspamd controller password.
	Password string `toml:"password"`

	// Timeout is the HTTP request timeout (e.g. "10s"). Defaults to 10s.
	Timeout string `toml:"timeout"`

	// RejectThreshold is the score at or above which messages are rejected (5xx).
	// nil means use rspamd's action field only (no threshold override).
	// Use a pointer so that 0.0 is a valid threshold and nil means "not set / inherit".
	RejectThreshold *float64 `toml:"reject_threshold"`

	// TempFailThreshold is the score at or above which messages receive a
	// temporary failure (4xx). nil means disabled.
	// Use a pointer so that 0.0 is a valid threshold and nil means "not set / inherit".
	TempFailThreshold *float64 `toml:"tempfail_threshold"`

	// FailMode controls behaviour when rspamd is unreachable.
	// Valid values: "open" (accept), "tempfail" (4xx), "reject" (5xx).
	// Defaults to "tempfail".
	FailMode string `toml:"fail_mode"`
}

// FileConfig is the top-level TOML wrapper for the shared config file.
// mail-deliver reads only the [maildeliver] section.
type FileConfig struct {
	MailDeliver Config `toml:"maildeliver"`
}

// IsEnabled reports whether spam checking is active for this config level.
// A nil Enabled field is treated as true (enabled by default when URL is set).
func (s *SpamConfig) IsEnabled() bool {
	if s.Enabled != nil && !*s.Enabled {
		return false
	}
	return s.URL != ""
}

// GetTimeout returns the configured timeout duration.
// Returns 10 seconds if not set or unparseable.
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

// Merge returns a new SpamConfig with non-zero values from override applied on
// top of the receiver. Used to layer user config over domain config over global.
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

// DataPath returns the effective data path: DomainsDataPath if set, else DomainsPath.
func (c *Config) DataPath() string {
	if c.DomainsDataPath != "" {
		return c.DomainsDataPath
	}
	return c.DomainsPath
}
