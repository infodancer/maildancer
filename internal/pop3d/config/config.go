// Package config provides configuration management for the POP3 server.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/infodancer/maildancer/internal/idrange"

	"github.com/infodancer/maildancer/internal/peergate"
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
	Server         ServerConfig         `toml:"server"`
	SessionManager SessionManagerConfig `toml:"session-manager"`
	Pop3d          Config               `toml:"pop3d"`
	PeerGate       peergate.Config      `toml:"peergate"`
}

// SessionManagerConfig holds connection settings for the session-manager service.
// This is a top-level [session-manager] section shared by all daemons.
type SessionManagerConfig struct {
	// Socket is the unix domain socket path for session-manager.
	Socket string `toml:"socket"`

	// Address is the TCP address for network mode (e.g. "session-manager:9443").
	// Requires CACert, ClientCert, and ClientKey for mTLS.
	Address string `toml:"address"`

	// CACert is the CA certificate path for verifying the server.
	CACert string `toml:"ca_cert"`

	// ClientCert is the client certificate path for mTLS authentication.
	ClientCert string `toml:"client_cert"`

	// ClientKey is the client private key path for mTLS authentication.
	ClientKey string `toml:"client_key"`
}

// IsEnabled returns true if a session-manager connection is configured.
func (c *SessionManagerConfig) IsEnabled() bool {
	return c.Socket != "" || c.Address != ""
}

// ServerConfig holds shared settings used by all mail services.
// These are read from the [server] section of the shared config file.
type ServerConfig struct {
	Hostname string    `toml:"hostname"`
	TLS      TLSConfig `toml:"tls"`
}

// Config holds the POP3-specific server configuration.
type Config struct {
	Hostname string `toml:"hostname"`
	LogLevel string `toml:"log_level"`
	// HandlerUID/HandlerGID/HandlerGroups are the credentials the
	// dispatcher drops each protocol-handler subprocess to; only the
	// per-connection handlers run under these ids. A zero HandlerUID (the
	// default) disables the drop: handlers inherit the dispatcher's
	// credentials, which keeps dev and rootless setups working. Mirrors
	// smtpd's handler credential model (#149).
	HandlerUID    uint32   `toml:"handler_uid"`
	HandlerGID    uint32   `toml:"handler_gid"`
	HandlerGroups []uint32 `toml:"handler_groups"`

	Listeners []ListenerConfig `toml:"listeners"`
	TLS       TLSConfig        `toml:"tls"`
	Timeouts  TimeoutsConfig   `toml:"timeouts"`
	Limits    LimitsConfig     `toml:"limits"`

	// PeerGate is the accept-time peer ban gate, read from the shared
	// top-level [peergate] section (#206). Populated by the loader.
	PeerGate       peergate.Config      `toml:"-"`
	Metrics        MetricsConfig        `toml:"metrics"`
	SessionManager SessionManagerConfig `toml:"-"` // populated from [session-manager] top-level section
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
	// SessionRecoveryDeadline bounds how long a protocol handler keeps
	// trying to transparently recover its session after a session-manager
	// restart before dropping the connection (#179,
	// session-recovery-design.md). Default 2m.
	SessionRecoveryDeadline string `toml:"session_recovery_deadline"`
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
			Connection:              "10m",
			Command:                 "1m",
			Idle:                    "30m",
			SessionRecoveryDeadline: "2m",
		},
		Limits: LimitsConfig{
			MaxConnections: 100,
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Address: ":9101",
			Path:    "/metrics",
		},
		PeerGate: peergate.Defaults(),
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

	if c.HandlerUID == 0 && (c.HandlerGID != 0 || len(c.HandlerGroups) > 0) {
		return errors.New("handler_gid/handler_groups require handler_uid")
	}
	if err := idrange.CheckHandlerIDs(c.HandlerUID, c.HandlerGID, c.HandlerGroups); err != nil {
		return err
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

	if c.Timeouts.SessionRecoveryDeadline != "" {
		if _, err := time.ParseDuration(c.Timeouts.SessionRecoveryDeadline); err != nil {
			return fmt.Errorf("invalid session recovery deadline: %w", err)
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

// RecoveryDeadline returns the session-recovery deadline as a time.Duration.
// Returns 2 minutes if not configured or invalid.
func (c *TimeoutsConfig) RecoveryDeadline() time.Duration {
	if c.SessionRecoveryDeadline == "" {
		return 2 * time.Minute
	}
	d, err := time.ParseDuration(c.SessionRecoveryDeadline)
	if err != nil {
		return 2 * time.Minute
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
