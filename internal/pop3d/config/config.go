// Package config provides configuration management for the POP3 server.
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
	// ModePop3 is standard POP3 on port 110 with optional STLS.
	ModePop3 ListenerMode = "pop3"
	// ModePop3s is implicit TLS on port 995.
	ModePop3s ListenerMode = "pop3s"
)

// FileConfig is the top-level wrapper for the shared configuration file.
// This allows smtpd, pop3d, and msgstore to share a single config file.
type FileConfig struct {
	Server ServerConfig `toml:"server"`
	Pop3d  Config       `toml:"pop3d"`
}

// ServerConfig holds shared settings used by all mail services.
type ServerConfig struct {
	Hostname string    `toml:"hostname"`
	Maildir  string    `toml:"maildir"`
	TLS      TLSConfig `toml:"tls"`
}

// Config holds the POP3-specific server configuration.
type Config struct {
	Hostname  string           `toml:"hostname"`
	LogLevel  string           `toml:"log_level"`
	Listeners []ListenerConfig `toml:"listeners"`
	TLS       TLSConfig        `toml:"tls"`
	Timeouts  TimeoutsConfig   `toml:"timeouts"`
	Limits    LimitsConfig     `toml:"limits"`
	Metrics   MetricsConfig    `toml:"metrics"`
	Maildir   string           `toml:"maildir"`
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
}

// LimitsConfig defines resource limits for the server.
type LimitsConfig struct {
	MaxConnections int `toml:"max_connections"`
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
			{Address: ":110", Mode: ModePop3},
		},
		TLS: TLSConfig{
			MinVersion: "1.2",
		},
		Timeouts: TimeoutsConfig{
			Connection: "10m",
			Command:    "1m",
			Idle:       "30m",
		},
		Limits: LimitsConfig{
			MaxConnections: 100,
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Address: ":9101",
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

var minTLSVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func isValidMode(m ListenerMode) bool {
	switch m {
	case ModePop3, ModePop3s:
		return true
	default:
		return false
	}
}
