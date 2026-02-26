package domain

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// DomainConfig is the per-domain configuration structure.
type DomainConfig struct {
	Auth     DomainAuthConfig     `toml:"auth"`
	MsgStore DomainMsgStoreConfig `toml:"msgstore"`
}

// DomainAuthConfig holds authentication settings for a domain.
type DomainAuthConfig struct {
	// Type is the auth agent type (e.g., "passwd", "ldap").
	Type string `toml:"type"`

	// CredentialBackend is the path to credential storage (relative to domain dir).
	CredentialBackend string `toml:"credential_backend"`

	// KeyBackend is the path to key storage (relative to domain dir).
	KeyBackend string `toml:"key_backend"`

	// Options contains backend-specific settings.
	Options map[string]string `toml:"options"`
}

// DomainMsgStoreConfig holds message storage settings for a domain.
type DomainMsgStoreConfig struct {
	// Type is the store type (e.g., "maildir").
	Type string `toml:"type"`

	// BasePath is the base directory for storage (relative to domain dir).
	BasePath string `toml:"base_path"`

	// Options contains backend-specific settings.
	Options map[string]string `toml:"options"`
}

// mergeConfig returns a new DomainConfig with base values overridden by
// non-zero values from override. Fields absent in override retain the base value.
func mergeConfig(base, override DomainConfig) DomainConfig {
	result := base
	if override.Auth.Type != "" {
		result.Auth.Type = override.Auth.Type
	}
	if override.Auth.CredentialBackend != "" {
		result.Auth.CredentialBackend = override.Auth.CredentialBackend
	}
	if override.Auth.KeyBackend != "" {
		result.Auth.KeyBackend = override.Auth.KeyBackend
	}
	if len(override.Auth.Options) > 0 {
		result.Auth.Options = override.Auth.Options
	}
	if override.MsgStore.Type != "" {
		result.MsgStore.Type = override.MsgStore.Type
	}
	if override.MsgStore.BasePath != "" {
		result.MsgStore.BasePath = override.MsgStore.BasePath
	}
	if len(override.MsgStore.Options) > 0 {
		result.MsgStore.Options = override.MsgStore.Options
	}
	return result
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
