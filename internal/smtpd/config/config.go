// Package config provides configuration management for the SMTP server.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"
)

// ListenerMode defines the operational mode for a listener.
type ListenerMode string

const (
	// ModeSmtp is standard SMTP on port 25.
	ModeSmtp ListenerMode = "smtp"
	// ModeSubmission is authenticated submission on port 587.
	ModeSubmission ListenerMode = "submission"
	// ModeSmtps is implicit TLS on port 465.
	ModeSmtps ListenerMode = "smtps"
	// ModeAlt is an alternative mode for custom configurations.
	ModeAlt ListenerMode = "alt"
)

// FileConfig is the top-level wrapper for the shared configuration file.
// This allows smtpd, pop3d, and msgstore to share a single config file.
type FileConfig struct {
	Smtpd Config `toml:"smtpd"`
}

// Config holds the complete SMTP server configuration.
type Config struct {
	Hostname  string           `toml:"hostname"`
	LogLevel  string           `toml:"log_level"`
	Listeners []ListenerConfig `toml:"listeners"`
	TLS       TLSConfig        `toml:"tls"`
	Limits    LimitsConfig     `toml:"limits"`
	Timeouts  TimeoutsConfig   `toml:"timeouts"`
	Metrics   MetricsConfig    `toml:"metrics"`
	Delivery  DeliveryConfig   `toml:"delivery"`
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

// LimitsConfig defines resource limits for the server.
type LimitsConfig struct {
	MaxMessageSize int `toml:"max_message_size"`
	MaxRecipients  int `toml:"max_recipients"`
}

// TimeoutsConfig defines timeout durations.
type TimeoutsConfig struct {
	Connection string `toml:"connection"`
	Command    string `toml:"command"`
}

// MetricsConfig holds configuration for Prometheus metrics.
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
	Path    string `toml:"path"`
}

// DeliveryConfig holds configuration for message delivery.
type DeliveryConfig struct {
	Maildir string `toml:"maildir"`
}

// Default returns a Config with sensible default values.
func Default() Config {
	return Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []ListenerConfig{
			{Address: ":25", Mode: ModeSmtp},
		},
		TLS: TLSConfig{
			MinVersion: "1.2",
		},
		Limits: LimitsConfig{
			MaxMessageSize: 26214400, // 25 MB
			MaxRecipients:  100,
		},
		Timeouts: TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Address: ":9100",
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

	if c.Limits.MaxMessageSize <= 0 {
		return errors.New("max_message_size must be positive")
	}

	if c.Limits.MaxRecipients <= 0 {
		return errors.New("max_recipients must be positive")
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
// Returns 5 minutes if not configured or invalid.
func (c *TimeoutsConfig) ConnectionTimeout() time.Duration {
	if c.Connection == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(c.Connection)
	if err != nil {
		return 5 * time.Minute
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

var minTLSVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func isValidMode(m ListenerMode) bool {
	switch m {
	case ModeSmtp, ModeSubmission, ModeSmtps, ModeAlt:
		return true
	default:
		return false
	}
}
