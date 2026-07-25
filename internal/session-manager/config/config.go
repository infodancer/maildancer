// Package config defines the session manager configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	"github.com/pelletier/go-toml/v2"
	"github.com/redis/go-redis/v9"
)

// Config holds all session manager settings.
type Config struct {
	// Socket is the unix domain socket path the session manager listens on.
	Socket string `toml:"socket"`

	// SocketGroup optionally names a group given connect access to the unix
	// socket: when set and running as root the socket is chowned
	// root:<group> and chmoded 0770 so unprivileged protocol daemons in
	// that group can reach it. Unset keeps the socket root-only (0600).
	SocketGroup string `toml:"socket_group"`

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

	// Redis is the shared Redis instance used for authentication rate limiting
	// and peer bans. Empty disables both: counters and bans have to be shared
	// across daemons and survive restarts to be worth anything (#206).
	Redis RedisConfig `toml:"redis"`

	// RateLimit configures authentication failure thresholds. Only enforced
	// when Redis is configured.
	RateLimit RateLimitConfig `toml:"ratelimit"`

	// PeerFilter configures connection-level bans for hostile peers.
	PeerFilter peerfilter.Config `toml:"peerfilter"`

	// LogLevel sets the minimum log level (debug, info, warn, error).
	// Default: info.
	LogLevel string `toml:"log_level"`
}

// RedisConfig holds the shared Redis connection settings.
type RedisConfig struct {
	// URL is the Redis connection URL (e.g. "redis://redis:6379/1").
	// Supports redis:// and rediss:// (TLS) schemes. Empty disables Redis.
	URL string `toml:"url"`

	// Password is the Redis AUTH password. Also settable via REDIS_PASSWORD.
	Password string `toml:"password"`
}

// Client builds a Redis client from the configuration. Returns (nil, nil) when
// no URL is set, which callers treat as "Redis-backed features are off" rather
// than as an error. Defined here so session-manager and userctl connect the
// same way to the same instance.
func (c RedisConfig) Client() (*redis.Client, error) {
	if c.URL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(c.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	if c.Password != "" {
		opts.Password = c.Password
	}
	return redis.NewClient(opts), nil
}

// RateLimitConfig holds authentication rate limit thresholds. It mirrors
// auth/domain.RateLimitConfig with TOML-friendly duration strings.
//
// There is deliberately no per-username threshold: locking an account across
// all source addresses is a cheap denial of service against a real user, and
// every username in the measured attack was nonexistent anyway (#206).
type RateLimitConfig struct {
	// Enabled turns authentication rate limiting on. Absent means enabled:
	// this ships secure by default. Requires Redis to be shared across
	// daemons; without it the in-process fallback still applies per process.
	// A pointer so an absent TOML key is distinguishable from an explicit
	// `enabled = false`.
	Enabled *bool `toml:"enabled"`

	// MaxFailuresPerIPUser is the failure budget for one (IP, username) pair
	// within the window. Default 5.
	MaxFailuresPerIPUser int `toml:"max_failures_per_ip_user"`

	// MaxFailuresPerIP is the failure budget for one address across all
	// usernames within the window. Default 20.
	MaxFailuresPerIP int `toml:"max_failures_per_ip"`

	// Window is how long a failure counts toward a threshold. Default 5m.
	Window time.Duration `toml:"-"`
	// WindowStr is the TOML-friendly form of Window.
	WindowStr string `toml:"window"`

	// Lockout is how long a lockout lasts once earned. Default 15m.
	Lockout time.Duration `toml:"-"`
	// LockoutStr is the TOML-friendly form of Lockout.
	LockoutStr string `toml:"lockout"`
}

// IsEnabled reports whether rate limiting should run. Absent configuration
// means enabled.
func (c *RateLimitConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// Normalize parses duration strings and fills zero values with the defaults
// from auth/domain.
func (c *RateLimitConfig) Normalize() error {
	d := domain.DefaultRateLimitConfig()

	if c.MaxFailuresPerIPUser == 0 {
		c.MaxFailuresPerIPUser = d.MaxFailuresPerIPUser
	}
	if c.MaxFailuresPerIP == 0 {
		c.MaxFailuresPerIP = d.MaxFailuresPerIP
	}
	for _, f := range []struct {
		name string
		str  string
		dst  *time.Duration
		def  time.Duration
	}{
		{"window", c.WindowStr, &c.Window, d.Window},
		{"lockout", c.LockoutStr, &c.Lockout, d.Lockout},
	} {
		if f.str != "" {
			parsed, err := time.ParseDuration(f.str)
			if err != nil {
				return fmt.Errorf("invalid ratelimit %s %q: %w", f.name, f.str, err)
			}
			*f.dst = parsed
		}
		if *f.dst == 0 {
			*f.dst = f.def
		}
	}
	return nil
}

// DomainConfig converts to the form auth/domain expects.
func (c *RateLimitConfig) DomainConfig() domain.RateLimitConfig {
	return domain.RateLimitConfig{
		MaxFailuresPerIPUser: c.MaxFailuresPerIPUser,
		MaxFailuresPerIP:     c.MaxFailuresPerIP,
		Window:               c.Window,
		Lockout:              c.Lockout,
	}
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

	// Owner optionally names the account that should own queue entries on
	// disk (e.g. "queued"). session-manager writes the queue privileged;
	// naming the (unprivileged) queue-manager account here keeps every new
	// entry readable by it. Empty leaves entries owned by this process.
	Owner string `toml:"owner"`
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

	// Keep the Redis password out of the config file when the deployment
	// prefers an environment variable, matching smtpd.
	if cfg.Redis.Password == "" {
		cfg.Redis.Password = os.Getenv("REDIS_PASSWORD")
	}

	if err := cfg.RateLimit.Normalize(); err != nil {
		return nil, err
	}
	if err := cfg.PeerFilter.Normalize(); err != nil {
		return nil, err
	}

	return cfg, nil
}
