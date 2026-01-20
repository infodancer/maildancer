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
	Server    ServerConfig    `toml:"server"`
	Smtpd     Config          `toml:"smtpd"`
	SpamCheck SpamCheckConfig `toml:"spamcheck"`
}

// ServerConfig holds shared settings used by all mail services.
type ServerConfig struct {
	Hostname string         `toml:"hostname"`
	Delivery DeliveryConfig `toml:"delivery"`
	TLS      TLSConfig      `toml:"tls"`
}

// Config holds the complete SMTP server configuration.
type Config struct {
	Hostname    string           `toml:"hostname"`
	LogLevel    string           `toml:"log_level"`
	DomainsPath string           `toml:"domains_path"`
	Listeners   []ListenerConfig `toml:"listeners"`
	TLS         TLSConfig        `toml:"tls"`
	Limits      LimitsConfig     `toml:"limits"`
	Timeouts    TimeoutsConfig   `toml:"timeouts"`
	Metrics     MetricsConfig    `toml:"metrics"`
	Delivery    DeliveryConfig   `toml:"delivery"`
	Encryption  EncryptionConfig `toml:"encryption"`
	Auth        AuthConfig       `toml:"auth"`
	SpamCheck   SpamCheckConfig  `toml:"spamcheck"`
}

// EncryptionConfig holds configuration for message encryption.
// When enabled, messages are encrypted for recipients that have keys configured.
type EncryptionConfig struct {
	// Enabled indicates whether message encryption is enabled.
	Enabled bool `toml:"enabled"`

	// KeyBackendType is the type of key provider (e.g., "passwd").
	KeyBackendType string `toml:"key_backend_type"`

	// KeyBackend is the path or connection string for key storage.
	// For passwd: path to key directory (e.g., "/etc/mail/keys")
	KeyBackend string `toml:"key_backend"`

	// CredentialBackend is the path for credential storage (needed by some key providers).
	// For passwd: path to passwd file (e.g., "/etc/mail/passwd")
	CredentialBackend string `toml:"credential_backend"`

	// Options contains implementation-specific settings.
	Options map[string]string `toml:"options"`
}

// IsEnabled returns true if encryption is enabled.
func (c *EncryptionConfig) IsEnabled() bool {
	return c.Enabled && c.KeyBackendType != ""
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
// Uses the msgstore registry pattern for pluggable storage backends.
type DeliveryConfig struct {
	Type     string            `toml:"type"`      // Storage backend type (e.g., "maildir")
	BasePath string            `toml:"base_path"` // Base path for storage
	Options  map[string]string `toml:"options"`   // Backend-specific options
}

// AuthConfig holds configuration for SMTP authentication.
type AuthConfig struct {
	Enabled           bool              `toml:"enabled"`
	AgentType         string            `toml:"agent_type"`         // Auth agent type (e.g., "passwd")
	CredentialBackend string            `toml:"credential_backend"` // Path to credential store
	KeyBackend        string            `toml:"key_backend"`        // Path to key store
	Options           map[string]string `toml:"options"`            // Backend-specific options
	OAuth             OAuthConfig       `toml:"oauth"`              // OAuth/OAUTHBEARER configuration
}

// OAuthConfig holds configuration for OAuth 2.0 bearer token authentication (RFC 7628).
type OAuthConfig struct {
	// Enabled indicates whether OAUTHBEARER mechanism is available.
	Enabled bool `toml:"enabled"`

	// JWKSURL is the URL to fetch the JSON Web Key Set for token validation.
	// Example: "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	JWKSURL string `toml:"jwks_url"`

	// Issuer is the expected "iss" claim in the JWT.
	// Example: "https://login.microsoftonline.com/{tenant}/v2.0"
	Issuer string `toml:"issuer"`

	// Audience is the expected "aud" claim in the JWT.
	// This is typically your application's client ID or API identifier.
	Audience string `toml:"audience"`

	// UsernameClaim specifies which JWT claim contains the username.
	// Common values: "email", "preferred_username", "sub", "upn"
	// Defaults to "email" if not specified.
	UsernameClaim string `toml:"username_claim"`

	// JWKSRefreshInterval is how often to refresh the JWKS (e.g., "1h").
	// Defaults to "1h" if not specified.
	JWKSRefreshInterval string `toml:"jwks_refresh_interval"`

	// AllowedDomains restricts which email domains can authenticate.
	// If empty, all domains are allowed.
	AllowedDomains []string `toml:"allowed_domains"`
}

// SpamCheckFailMode defines the behavior when spam checkers are unavailable or error.
type SpamCheckFailMode string

const (
	// SpamCheckFailOpen accepts the message when checkers are unavailable.
	SpamCheckFailOpen SpamCheckFailMode = "open"
	// SpamCheckFailTempFail returns a temporary failure (4xx) when checkers are unavailable.
	SpamCheckFailTempFail SpamCheckFailMode = "tempfail"
	// SpamCheckFailReject returns a permanent failure (5xx) when checkers are unavailable.
	SpamCheckFailReject SpamCheckFailMode = "reject"
)

// SpamCheckConfig holds configuration for spam filtering.
type SpamCheckConfig struct {
	// Enabled indicates whether spam checking is enabled.
	Enabled bool `toml:"enabled"`

	// Checkers is the list of spam checkers to use.
	Checkers []SpamCheckerConfig `toml:"checkers"`

	// Mode determines how multiple checker results are aggregated.
	// "first_reject" - reject if any checker says reject (default)
	// "all_reject" - reject only if all checkers say reject
	// "highest_score" - use the result with the highest score
	Mode string `toml:"mode"`

	// FailMode determines behavior when checkers are unavailable.
	FailMode SpamCheckFailMode `toml:"fail_mode"`

	// RejectThreshold is the score at or above which messages are rejected (5xx).
	RejectThreshold float64 `toml:"reject_threshold"`

	// TempFailThreshold is the score at or above which messages get temp failure (4xx).
	TempFailThreshold float64 `toml:"tempfail_threshold"`

	// AddHeaders indicates whether to add spam headers to messages.
	AddHeaders bool `toml:"add_headers"`
}

// SpamCheckerConfig holds configuration for a single spam checker.
type SpamCheckerConfig struct {
	// Type is the checker type: "rspamd", "spamassassin", etc.
	Type string `toml:"type"`

	// Enabled indicates whether this checker is enabled (default true).
	Enabled *bool `toml:"enabled"`

	// URL is the endpoint for HTTP-based checkers.
	URL string `toml:"url"`

	// Password is the optional password/secret for the checker.
	Password string `toml:"password"`

	// Timeout is the request timeout (e.g., "10s").
	Timeout string `toml:"timeout"`

	// Options contains checker-specific options.
	Options map[string]string `toml:"options"`
}

// IsEnabled returns true if spam checking is enabled and has at least one checker.
func (c *SpamCheckConfig) IsEnabled() bool {
	if !c.Enabled {
		return false
	}
	for _, checker := range c.Checkers {
		if checker.IsEnabled() {
			return true
		}
	}
	return false
}

// GetFailMode returns the fail mode, defaulting to tempfail if not set.
func (c *SpamCheckConfig) GetFailMode() SpamCheckFailMode {
	switch c.FailMode {
	case SpamCheckFailOpen, SpamCheckFailTempFail, SpamCheckFailReject:
		return c.FailMode
	default:
		return SpamCheckFailTempFail
	}
}

// IsEnabled returns true if this checker is enabled.
func (c *SpamCheckerConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true // default to enabled
	}
	return *c.Enabled
}

// GetTimeout returns the timeout as a time.Duration.
func (c *SpamCheckerConfig) GetTimeout() time.Duration {
	if c.Timeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// IsEnabled returns true if authentication is enabled.
func (c *AuthConfig) IsEnabled() bool {
	return c.Enabled && c.AgentType != ""
}

// IsEnabled returns true if OAuth authentication is enabled and properly configured.
func (c *OAuthConfig) IsEnabled() bool {
	return c.Enabled && c.JWKSURL != ""
}

// GetUsernameClaim returns the configured username claim, defaulting to "email".
func (c *OAuthConfig) GetUsernameClaim() string {
	if c.UsernameClaim == "" {
		return "email"
	}
	return c.UsernameClaim
}

// GetJWKSRefreshInterval returns the JWKS refresh interval as a time.Duration.
// Returns 1 hour if not configured or invalid.
func (c *OAuthConfig) GetJWKSRefreshInterval() time.Duration {
	if c.JWKSRefreshInterval == "" {
		return 1 * time.Hour
	}
	d, err := time.ParseDuration(c.JWKSRefreshInterval)
	if err != nil {
		return 1 * time.Hour
	}
	return d
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

	// Validate encryption config
	if c.Encryption.Enabled {
		if c.Encryption.KeyBackendType == "" {
			return errors.New("encryption.key_backend_type is required when encryption is enabled")
		}
		if c.Encryption.KeyBackend == "" {
			return errors.New("encryption.key_backend is required when encryption is enabled")
		}
	}

	// Validate auth config
	if c.Auth.Enabled {
		if c.Auth.AgentType == "" {
			return errors.New("auth.agent_type is required when authentication is enabled")
		}
		if c.Auth.CredentialBackend == "" {
			return errors.New("auth.credential_backend is required when authentication is enabled")
		}
	}

	// Validate OAuth config
	if c.Auth.OAuth.Enabled {
		if c.Auth.OAuth.JWKSURL == "" {
			return errors.New("auth.oauth.jwks_url is required when OAuth is enabled")
		}
		if c.Auth.OAuth.Issuer == "" {
			return errors.New("auth.oauth.issuer is required when OAuth is enabled")
		}
		if c.Auth.OAuth.Audience == "" {
			return errors.New("auth.oauth.audience is required when OAuth is enabled")
		}
		if c.Auth.OAuth.JWKSRefreshInterval != "" {
			if _, err := time.ParseDuration(c.Auth.OAuth.JWKSRefreshInterval); err != nil {
				return fmt.Errorf("invalid auth.oauth.jwks_refresh_interval: %w", err)
			}
		}
	}

	// Validate spamcheck config
	if c.SpamCheck.Enabled {
		for i, checker := range c.SpamCheck.Checkers {
			if checker.Type == "" {
				return fmt.Errorf("spamcheck.checkers[%d].type is required", i)
			}
			if checker.Timeout != "" {
				if _, err := time.ParseDuration(checker.Timeout); err != nil {
					return fmt.Errorf("invalid spamcheck.checkers[%d].timeout: %w", i, err)
				}
			}
			// Validate checker-specific requirements
			switch checker.Type {
			case "rspamd":
				if checker.URL == "" {
					return fmt.Errorf("spamcheck.checkers[%d].url is required for rspamd", i)
				}
			case "spamassassin":
				if checker.URL == "" {
					return fmt.Errorf("spamcheck.checkers[%d].url is required for spamassassin", i)
				}
			}
		}
		switch c.SpamCheck.FailMode {
		case "", SpamCheckFailOpen, SpamCheckFailTempFail, SpamCheckFailReject:
			// valid
		default:
			return fmt.Errorf("invalid spamcheck.fail_mode %q (valid: open, tempfail, reject)", c.SpamCheck.FailMode)
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
