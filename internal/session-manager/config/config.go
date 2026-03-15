// Package config defines the session manager configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config holds all session manager settings.
type Config struct {
	// Socket is the unix domain socket path the session manager listens on.
	Socket string `toml:"socket"`

	// DomainsPath is the directory containing per-domain subdirectories
	// (each with config.toml, passwd, etc.).
	DomainsPath string `toml:"domains_path"`

	// DomainsDataPath is an optional separate directory for per-domain data.
	// Defaults to DomainsPath if empty.
	DomainsDataPath string `toml:"domains_data_path"`

	// MailSessionCmd is the absolute path to the mail-session binary.
	MailSessionCmd string `toml:"mail_session_cmd"`

	// IdleTimeout is how long a mail-session process lingers after its last
	// connection disconnects. Default: 5m.
	IdleTimeout time.Duration `toml:"-"`

	// IdleTimeoutStr is the TOML-friendly string form of IdleTimeout.
	IdleTimeoutStr string `toml:"idle_timeout"`

	// Listen is an optional TCP address (e.g. "0.0.0.0:9443") for network mode.
	// When set, the server listens on TCP with mTLS instead of (or in addition to)
	// a unix socket. Requires TLS config.
	Listen string `toml:"listen"`

	// TLS configures mTLS for network mode.
	TLS TLSConfig `toml:"tls"`

	// Auth configures the authentication backend.
	Auth AuthConfig `toml:"auth"`

	// Queue configures outbound mail queue injection.
	Queue QueueConfig `toml:"queue"`

	// Metrics configures the Prometheus metrics endpoint.
	Metrics MetricsConfig `toml:"metrics"`
}

// QueueConfig holds outbound queue injection settings.
type QueueConfig struct {
	// Dir is the root of the on-disk mail queue (e.g. "/var/spool/mail-queue").
	Dir string `toml:"dir"`

	// MessageTTL is how long the message should be retried (e.g. "168h").
	// Default: 168h (7 days).
	MessageTTL string `toml:"message_ttl"`

	// Hostname is the VERP domain. Falls back to the system hostname if empty.
	Hostname string `toml:"hostname"`
}

// GetMessageTTL parses MessageTTL as a duration, defaulting to 7 days.
func (q *QueueConfig) GetMessageTTL() time.Duration {
	if q.MessageTTL == "" {
		return 7 * 24 * time.Hour
	}
	d, err := time.ParseDuration(q.MessageTTL)
	if err != nil {
		return 7 * 24 * time.Hour
	}
	return d
}

// TLSConfig holds certificate paths for mTLS.
type TLSConfig struct {
	// CACert is the path to the CA certificate used to verify client certs.
	CACert string `toml:"ca_cert"`

	// CAKey is the path to the CA private key (only needed for cert subcommand).
	CAKey string `toml:"ca_key"`

	// ServerCert is the path to the server certificate.
	ServerCert string `toml:"server_cert"`

	// ServerKey is the path to the server private key.
	ServerKey string `toml:"server_key"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	// Enabled controls whether the metrics HTTP server is started.
	Enabled bool `toml:"enabled"`

	// Address is the listen address for the metrics HTTP server (e.g. ":9100").
	Address string `toml:"address"`

	// Path is the HTTP path for the metrics endpoint (e.g. "/metrics").
	Path string `toml:"path"`
}

// AuthConfig controls how the session manager authenticates users.
type AuthConfig struct {
	// AgentType is the auth backend type (e.g. "passwd").
	AgentType string `toml:"agent_type"`

	// CredentialBackend is the default credential backend path.
	// Per-domain config can override this.
	CredentialBackend string `toml:"credential_backend"`

	// KeyBackend is the default key backend path.
	KeyBackend string `toml:"key_backend"`
}

// ServerConfig holds shared settings from the [server] section.
type ServerConfig struct {
	Hostname        string `toml:"hostname"`
	DomainsPath     string `toml:"domains_path"`
	DomainsDataPath string `toml:"domains_data_path"`
	Maildir         string `toml:"maildir"` // alias for domains_data_path (used by webadmin)
}

// fileConfig is the parse target for the shared config file.
type fileConfig struct {
	Server         ServerConfig `toml:"server"`
	SessionManager Config       `toml:"session-manager"`
}

// Load reads the config from a TOML file.
// Global settings (domains_path, domains_data_path) are read from [server];
// session-manager-specific settings come from [session-manager].
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var fc fileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg := &fc.SessionManager

	// Merge [server] globals into session-manager config.
	if cfg.DomainsPath == "" && fc.Server.DomainsPath != "" {
		cfg.DomainsPath = fc.Server.DomainsPath
	}
	if cfg.DomainsDataPath == "" {
		if fc.Server.DomainsDataPath != "" {
			cfg.DomainsDataPath = fc.Server.DomainsDataPath
		} else if fc.Server.Maildir != "" {
			cfg.DomainsDataPath = fc.Server.Maildir
		}
	}

	// Parse idle timeout.
	if cfg.IdleTimeoutStr != "" {
		d, err := time.ParseDuration(cfg.IdleTimeoutStr)
		if err != nil {
			return nil, fmt.Errorf("invalid idle_timeout %q: %w", cfg.IdleTimeoutStr, err)
		}
		cfg.IdleTimeout = d
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}

	return cfg, nil
}
