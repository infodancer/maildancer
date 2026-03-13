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

// Load reads the config from a TOML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Wrap in a top-level section.
	var wrapper struct {
		SessionManager Config `toml:"session-manager"`
	}
	if err := toml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg := &wrapper.SessionManager

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
