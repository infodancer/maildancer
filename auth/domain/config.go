package domain

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// DomainConfig is the per-domain configuration structure.
// All fields use omitempty so that TOML-level deep merge correctly skips
// zero values — only explicitly set fields override lower-priority layers.
type DomainConfig struct {
	Auth     DomainAuthConfig     `toml:"auth,omitempty"`
	MsgStore DomainMsgStoreConfig `toml:"msgstore,omitempty"`
	DKIM     DKIMConfig           `toml:"dkim,omitempty"`
	Outbound OutboundConfig       `toml:"outbound,omitempty"`
	Limits   LimitsConfig         `toml:"limits,omitempty"`

	// Gid is the OS group ID under which mail-session runs for this domain.
	// 0 means not configured.
	Gid uint32 `toml:"gid,omitempty"`

	// MaxMessageSize is the maximum message size in bytes for this domain.
	// Applies to both delivery (mail-deliver) and rspamd learning (mail-session).
	// 0 means use the global default (50 MiB).
	MaxMessageSize int64 `toml:"max_message_size,omitempty"`

	// RecipientRejection controls when unknown recipients are rejected.
	// "rcpt" = reject at RCPT TO (default); "data" = defer rejection to after DATA.
	RecipientRejection string `toml:"recipient_rejection,omitempty"`

	// Forwards maps localpart to comma-separated forwarding targets.
	// The special key "*" is a catchall. A nil map means "not set" and allows
	// the system default forwards to apply. An empty non-nil map (forwards = {})
	// explicitly disables forwarding for this domain.
	Forwards map[string]string `toml:"forwards,omitempty"`
}

// DomainAuthConfig holds authentication settings for a domain.
type DomainAuthConfig struct {
	// Type is the auth agent type (e.g., "passwd", "ldap").
	Type string `toml:"type,omitempty"`

	// CredentialBackend is the path to credential storage (relative to domain dir).
	CredentialBackend string `toml:"credential_backend,omitempty"`

	// KeyBackend is the path to key storage (relative to domain dir).
	KeyBackend string `toml:"key_backend,omitempty"`

	// Options contains backend-specific settings.
	Options map[string]string `toml:"options,omitempty"`
}

// DomainMsgStoreConfig holds message storage settings for a domain.
type DomainMsgStoreConfig struct {
	// Type is the store type (e.g., "maildir").
	Type string `toml:"type,omitempty"`

	// BasePath is the base directory for storage (relative to domain dir).
	BasePath string `toml:"base_path,omitempty"`

	// Options contains backend-specific settings.
	Options map[string]string `toml:"options,omitempty"`
}

// DKIMConfig holds DKIM signing configuration for a domain.
type DKIMConfig struct {
	// Selector is the DKIM selector name (e.g., "default", "sel1").
	// Published in DNS as selector._domainkey.domain.
	Selector string `toml:"selector,omitempty"`

	// PrivateKeyPath is the path to the Ed25519 private key in PEM format.
	PrivateKeyPath string `toml:"private_key,omitempty"`
}

// OutboundConfig holds per-domain outbound delivery transport settings.
// Used by queue-manager to determine how to deliver mail from this domain.
type OutboundConfig struct {
	// Strategy is the delivery method: "direct" for MX delivery, "smarthost" for relay.
	// Default is "direct".
	Strategy string `toml:"strategy,omitempty"`

	// Smarthost is the relay address in host:port form.
	// Required when Strategy is "smarthost".
	Smarthost string `toml:"smarthost,omitempty"`

	// SmarthostUser is the SMTP AUTH username for the smarthost.
	SmarthostUser string `toml:"smarthost_user,omitempty"`

	// PasswordFile is the path to a file containing the SMTP AUTH password.
	// Relative paths resolve from the domain directory.
	PasswordFile string `toml:"password_file,omitempty"`
}

// LimitsConfig holds rate limiting and resource limit settings for a domain.
type LimitsConfig struct {
	// MaxSendsPerHour is the maximum messages an authenticated sender on this
	// domain may send per hour. 0 means use the global default.
	MaxSendsPerHour int `toml:"max_sends_per_hour,omitempty"`
}

// DomainsConfig holds per-domain configuration overrides from domains.toml.
// Keys are domain names (e.g. "matthewjayhunter.com").
// This file is managed by the system postmaster and provides per-domain settings
// that domain admins can further override in their own config.toml.
type DomainsConfig map[string]DomainConfig

// LoadDomainsConfig reads and parses a domains.toml file.
// A missing file is not an error — returns an empty DomainsConfig.
func LoadDomainsConfig(path string) (DomainsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(DomainsConfig), nil
		}
		return nil, fmt.Errorf("read domains config: %w", err)
	}
	var cfg DomainsConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse domains config: %w", err)
	}
	return cfg, nil
}

// LoadDomainConfig reads and parses a domain configuration file.
func LoadDomainConfig(path string) (*DomainConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg DomainConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}
