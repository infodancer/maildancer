// Package config provides configuration management for the IMAP server.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// upstreamIdleSlop is the safety margin reserved below upstream_session_idle
// when validating session_keepalive. Covers RPC latency and clock drift.
const upstreamIdleSlop = 60 * time.Second

// ListenerMode defines the operational mode for a listener.
type ListenerMode string

const (
	// ModeImap is standard IMAP on port 143 with optional STARTTLS.
	ModeImap ListenerMode = "imap"
	// ModeImaps is implicit TLS on port 993.
	ModeImaps ListenerMode = "imaps"
)

// SessionManagerConfig holds configuration for connecting to the session-manager service.
type SessionManagerConfig struct {
	Socket     string `toml:"socket"`
	Address    string `toml:"address"`
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
}

// IsEnabled returns true if session-manager is configured.
func (c *SessionManagerConfig) IsEnabled() bool {
	return c.Socket != "" || c.Address != ""
}

// FileConfig is the top-level wrapper for the shared configuration file.
// This allows smtpd, pop3d, imapd, and msgstore to share a single config file.
type FileConfig struct {
	Server         ServerConfig         `toml:"server"`
	Imapd          Config               `toml:"imapd"`
	Redis          RedisConfig          `toml:"redis"`
	SessionManager SessionManagerConfig `toml:"session-manager"`
}

// ServerConfig holds shared settings used by all mail services.
// These are read from the [server] section of the shared config file.
type ServerConfig struct {
	Hostname string    `toml:"hostname"`
	TLS      TLSConfig `toml:"tls"`
}

// RedisConfig holds Redis connection settings for pub/sub notifications.
type RedisConfig struct {
	// URL is the Redis connection URL (e.g. "redis://redis:6379/1").
	// Empty disables Redis notifications.
	URL string `toml:"url"`
	// Password is the optional Redis AUTH password.
	Password string `toml:"password"`
}

// RspamdConfig holds configuration for rspamd ham/spam learning.
type RspamdConfig struct {
	// Controller is the rspamd HTTP controller URL (e.g. "http://rspamd:11334").
	// Empty disables learning.
	Controller string `toml:"controller"`
	// JunkFolder is the name of the Junk/Spam folder that triggers learning.
	// Defaults to "Junk" when empty.
	JunkFolder string `toml:"junk_folder"`
}

// Config holds the IMAP-specific server configuration.
type Config struct {
	Hostname       string               `toml:"hostname"`
	LogLevel       string               `toml:"log_level"`
	Listeners      []ListenerConfig     `toml:"listeners"`
	TLS            TLSConfig            `toml:"tls"`
	Timeouts       TimeoutsConfig       `toml:"timeouts"`
	Limits         LimitsConfig         `toml:"limits"`
	Metrics        MetricsConfig        `toml:"metrics"`
	Rspamd         RspamdConfig         `toml:"rspamd"`
	Redis          RedisConfig          `toml:"redis"`
	SessionManager SessionManagerConfig `toml:"-"` // populated by loader from top-level [session-manager]
}

// ListenerConfig defines settings for a single listener.
type ListenerConfig struct {
	Address string       `toml:"address"`
	Mode    ListenerMode `toml:"mode"`
}

// TLSConfig holds TLS certificate and version settings.
type TLSConfig struct {
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	MinVersion string `toml:"min_version"`
}

// TimeoutsConfig defines timeout durations.
type TimeoutsConfig struct {
	Connection string `toml:"connection"`
	Command    string `toml:"command"`
	Idle       string `toml:"idle"`
	// SessionKeepalive is the interval at which an IDLE'ing connection sends
	// a no-op RPC to session-manager to keep the upstream mail-session
	// subprocess from reaping itself. Must be safely below the upstream
	// idle timeout (mail-session default is 30m). Zero disables keepalive.
	SessionKeepalive string `toml:"session_keepalive"`
	// UpstreamSessionIdle is the operator's declared value for mail-session's
	// own --idle-timeout. imapd uses this to validate SessionKeepalive at
	// startup. Default 30m matches mail-session's daemon-mode default.
	UpstreamSessionIdle string `toml:"upstream_session_idle"`
}

// LimitsConfig defines resource limits for the server.
type LimitsConfig struct {
	MaxConnections int   `toml:"max_connections"`
	MaxMessageSize int64 `toml:"max_message_size"`
}

// MetricsConfig holds configuration for Prometheus metrics.
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
	Path    string `toml:"path"`
}

// Default returns a Config with sensible default values.
func Default() Config {
	return Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []ListenerConfig{
			{Address: ":143", Mode: ModeImap},
		},
		TLS: TLSConfig{
			MinVersion: "1.2",
		},
		Timeouts: TimeoutsConfig{
			Connection:          "10m",
			Command:             "1m",
			Idle:                "30m",
			SessionKeepalive:    "5m",
			UpstreamSessionIdle: "30m",
		},
		Limits: LimitsConfig{
			MaxConnections: 200,
			MaxMessageSize: 52428800, // 50 MiB
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Address: ":9102",
			Path:    "/metrics",
		},
	}
}

// Validate checks that the configuration is valid and returns an error if not.
func (c *Config) Validate() error {
	if c.Hostname == "" {
		return errors.New("hostname is required")
	}

	if len(c.Listeners) == 0 {
		return errors.New("at least one listener is required")
	}

	for i, l := range c.Listeners {
		if l.Address == "" {
			return fmt.Errorf("listener %d: address is required", i)
		}
		if !isValidMode(l.Mode) {
			return fmt.Errorf("listener %d: invalid mode %q", i, l.Mode)
		}
	}

	if c.Limits.MaxConnections <= 0 {
		return errors.New("max_connections must be positive")
	}

	if c.Timeouts.Connection != "" {
		if _, err := time.ParseDuration(c.Timeouts.Connection); err != nil {
			return fmt.Errorf("invalid connection timeout: %w", err)
		}
	}

	if c.Timeouts.Command != "" {
		if _, err := time.ParseDuration(c.Timeouts.Command); err != nil {
			return fmt.Errorf("invalid command timeout: %w", err)
		}
	}

	if c.Timeouts.Idle != "" {
		if _, err := time.ParseDuration(c.Timeouts.Idle); err != nil {
			return fmt.Errorf("invalid idle timeout: %w", err)
		}
	}

	if c.Timeouts.SessionKeepalive != "" {
		if _, err := time.ParseDuration(c.Timeouts.SessionKeepalive); err != nil {
			return fmt.Errorf("invalid session keepalive: %w", err)
		}
	}

	if c.Timeouts.UpstreamSessionIdle != "" {
		if _, err := time.ParseDuration(c.Timeouts.UpstreamSessionIdle); err != nil {
			return fmt.Errorf("invalid upstream session idle: %w", err)
		}
	}

	if c.TLS.MinVersion != "" {
		if _, ok := minTLSVersions[c.TLS.MinVersion]; !ok {
			return fmt.Errorf("invalid TLS min_version %q (valid: 1.0, 1.1, 1.2, 1.3)", c.TLS.MinVersion)
		}
	}

	if c.Metrics.Enabled {
		if c.Metrics.Address == "" {
			return errors.New("metrics address is required when metrics are enabled")
		}
		if c.Metrics.Path == "" {
			return errors.New("metrics path is required when metrics are enabled")
		}
	}

	return nil
}

// MinTLSVersion returns the crypto/tls constant for the configured minimum TLS version.
// Returns tls.VersionTLS12 if not configured or invalid.
func (c *TLSConfig) MinTLSVersion() uint16 {
	if v, ok := minTLSVersions[c.MinVersion]; ok {
		return v
	}
	return tls.VersionTLS12
}

// ConnectionTimeout returns the connection timeout as a time.Duration.
// Returns 10 minutes if not configured or invalid.
func (c *TimeoutsConfig) ConnectionTimeout() time.Duration {
	if c.Connection == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(c.Connection)
	if err != nil {
		return 10 * time.Minute
	}
	return d
}

// CommandTimeout returns the command timeout as a time.Duration.
// Returns 1 minute if not configured or invalid.
func (c *TimeoutsConfig) CommandTimeout() time.Duration {
	if c.Command == "" {
		return 1 * time.Minute
	}
	d, err := time.ParseDuration(c.Command)
	if err != nil {
		return 1 * time.Minute
	}
	return d
}

// IdleTimeout returns the idle timeout as a time.Duration.
// Returns 30 minutes if not configured or invalid.
func (c *TimeoutsConfig) IdleTimeout() time.Duration {
	if c.Idle == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(c.Idle)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// SessionKeepaliveInterval returns the IDLE-time keepalive interval as a
// time.Duration. Returns 5 minutes if not configured or invalid. Returns 0
// only if explicitly set to "0" (disabled).
func (c *TimeoutsConfig) SessionKeepaliveInterval() time.Duration {
	if c.SessionKeepalive == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(c.SessionKeepalive)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// UpstreamSessionIdleTimeout returns the declared mail-session idle timeout
// that imapd validates SessionKeepalive against. Returns 30 minutes if not
// configured or invalid (matches mail-session's daemon-mode default).
func (c *TimeoutsConfig) UpstreamSessionIdleTimeout() time.Duration {
	if c.UpstreamSessionIdle == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(c.UpstreamSessionIdle)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// NormalizeSessionKeepalive clamps SessionKeepalive to a safe value below
// UpstreamSessionIdle if the operator-supplied value would race the upstream
// reaper. The clamp is to upstream/2, which gives at least one safe tick
// before the upstream idle timer would fire even if the first tick misses.
// Mutates c in place; logs a warning when an adjustment is made.
//
// Returns true if the value was adjusted.
func (c *TimeoutsConfig) NormalizeSessionKeepalive(logger *slog.Logger) bool {
	if logger == nil {
		logger = slog.Default()
	}
	keepalive := c.SessionKeepaliveInterval()
	upstream := c.UpstreamSessionIdleTimeout()
	if keepalive <= 0 {
		// Explicit zero disables keepalive entirely; trust the operator.
		return false
	}
	if keepalive+upstreamIdleSlop < upstream {
		return false
	}
	clamped := upstream / 2
	logger.Warn("session_keepalive is too close to upstream_session_idle; clamping to upstream/2",
		"configured_keepalive", keepalive,
		"upstream_session_idle", upstream,
		"slop", upstreamIdleSlop,
		"clamped_keepalive", clamped,
		"reason", "keepalive must fire well before upstream mail-session reaps itself")
	c.SessionKeepalive = clamped.String()
	return true
}

var minTLSVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func isValidMode(m ListenerMode) bool {
	switch m {
	case ModeImap, ModeImaps:
		return true
	default:
		return false
	}
}
