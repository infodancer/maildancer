// Package config handles TOML configuration for the webadmin server.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level configuration structure.
type Config struct {
	WebAdmin WebAdminConfig `toml:"webadmin"`
}

// PrometheusConfig holds optional Prometheus integration settings.
type PrometheusConfig struct {
	// URLs is a list of Prometheus base URLs to query for mail server metrics.
	// When multiple URLs are configured, results are aggregated (summed) across
	// all instances, supporting multi-node deployments. If empty, mail server
	// stats are unavailable on the dashboard.
	URLs []string `toml:"urls"`
}

// WebAdminConfig holds all webadmin-specific settings.
type WebAdminConfig struct {
	// ListenAddress is the address to listen on (default: "localhost:8080").
	ListenAddress string `toml:"listen_address"`

	// DomainsPath is the base directory containing per-domain config directories
	// (passwd files, auth config, DKIM keys). This is the config volume.
	DomainsPath string `toml:"domains_path"`

	// DataPath is the base directory for per-domain mail data (maildirs, uid counter, gid config).
	// This is the data volume. If empty, defaults to DomainsPath for backward compatibility.
	DataPath string `toml:"data_path"`

	// LogLevel controls logging verbosity (debug, info, warn, error).
	LogLevel string `toml:"log_level"`

	// TLS holds optional TLS configuration.
	TLS TLSConfig `toml:"tls"`

	// Auth holds admin authentication configuration.
	Auth AuthConfig `toml:"auth"`

	// Session holds session management configuration.
	Session SessionConfig `toml:"session"`

	// Audit holds audit logging configuration.
	Audit AuditConfig `toml:"audit"`

	// Prometheus holds optional Prometheus integration for mail server stats.
	Prometheus PrometheusConfig `toml:"prometheus"`

	// PermCheck configures the periodic permission-drift sweep that feeds
	// the webadmin_domain_perm_drift gauge.
	PermCheck PermCheckConfig `toml:"perm_check"`

	// FilePath is the path to the config file this struct was loaded from.
	// Not a TOML field -- set programmatically by Load(). Used by handlers
	// that need to write back to the shared config file (e.g. rspamd settings).
	FilePath string `toml:"-"`
}

// TLSConfig holds TLS certificate configuration.
type TLSConfig struct {
	// CertFile is the path to the TLS certificate file.
	CertFile string `toml:"cert_file"`

	// KeyFile is the path to the TLS private key file.
	KeyFile string `toml:"key_file"`
}

// AuthConfig holds admin authentication settings.
type AuthConfig struct {
	// PasswdFile is the path to the admin passwd file.
	PasswdFile string `toml:"passwd_file"`

	// RolesFile is the optional path to roles.toml for RBAC.
	// If empty, all authenticated admins are treated as super_admin.
	RolesFile string `toml:"roles_file"`
}

// AuditConfig holds audit logging settings.
type AuditConfig struct {
	// LogFile is the path to write JSON audit log lines.
	// If empty, audit events go to slog only.
	LogFile string `toml:"log_file"`
}

// PermCheckConfig holds settings for the periodic permission-drift sweep.
type PermCheckConfig struct {
	// Interval is the time between drift sweeps as a Go duration string
	// (e.g. "1h", "30m"). Empty means the default of 1h; "0" disables the
	// sweep entirely.
	Interval string `toml:"interval"`
}

// SessionConfig holds session management settings.
type SessionConfig struct {
	// TimeoutMinutes is the session timeout in minutes (default: 30).
	TimeoutMinutes int `toml:"timeout_minutes"`
}

// Defaults applies default values to unset fields.
func (c *Config) Defaults() {
	if c.WebAdmin.ListenAddress == "" {
		c.WebAdmin.ListenAddress = "localhost:8080"
	}
	if c.WebAdmin.LogLevel == "" {
		c.WebAdmin.LogLevel = "info"
	}
	if c.WebAdmin.Session.TimeoutMinutes == 0 {
		c.WebAdmin.Session.TimeoutMinutes = 30
	}
}

// Validate checks the configuration for required fields.
func (c *Config) Validate() error {
	if c.WebAdmin.DomainsPath == "" {
		return fmt.Errorf("webadmin.domains_path is required")
	}
	if c.WebAdmin.Auth.PasswdFile == "" {
		return fmt.Errorf("webadmin.auth.passwd_file is required")
	}
	if c.WebAdmin.TLS.CertFile != "" && c.WebAdmin.TLS.KeyFile == "" {
		return fmt.Errorf("webadmin.tls.key_file is required when cert_file is set")
	}
	if c.WebAdmin.TLS.KeyFile != "" && c.WebAdmin.TLS.CertFile == "" {
		return fmt.Errorf("webadmin.tls.cert_file is required when key_file is set")
	}
	if _, err := c.WebAdmin.PermCheckInterval(); err != nil {
		return err
	}
	return nil
}

// PermCheckInterval returns the parsed permission-drift sweep interval.
// Empty defaults to 1h; zero disables the sweep.
func (c *WebAdminConfig) PermCheckInterval() (time.Duration, error) {
	if c.PermCheck.Interval == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(c.PermCheck.Interval)
	if err != nil {
		return 0, fmt.Errorf("webadmin.perm_check.interval: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("webadmin.perm_check.interval must not be negative")
	}
	return d, nil
}

// EffectiveDataPath returns DataPath if set, otherwise DomainsPath (backward compat).
func (c *WebAdminConfig) EffectiveDataPath() string {
	if c.DataPath != "" {
		return c.DataPath
	}
	return c.DomainsPath
}

// TLSEnabled returns whether TLS is configured.
func (c *WebAdminConfig) TLSEnabled() bool {
	return c.TLS.CertFile != "" && c.TLS.KeyFile != ""
}

// Load reads and parses a TOML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	cfg.WebAdmin.FilePath = path
	cfg.Defaults()
	return &cfg, nil
}
