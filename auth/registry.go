package auth

import (
	"sort"
	"sync"

	"github.com/infodancer/maildancer/auth/errors"
)

// AuthAgentFactory creates an AuthenticationAgent from configuration.
type AuthAgentFactory func(config AuthAgentConfig) (AuthenticationAgent, error)

// AuthAgentConfig contains settings for opening an authentication agent.
type AuthAgentConfig struct {
	// Type is the auth agent type name (e.g., "passwd", "ldap", "database").
	Type string

	// CredentialBackend is the path or connection string for credential storage.
	// For passwd: path to the passwd file (e.g., "/etc/mail/passwd")
	// For LDAP: connection URL (e.g., "ldaps://ldap.example.com")
	// For database: connection string
	CredentialBackend string

	// KeyBackend is the path or connection string for key storage.
	// Can differ from CredentialBackend (e.g., LDAP for credentials,
	// local filesystem for keys).
	// For passwd/LDAP with local keys: path to key directory (e.g., "/etc/mail/keys")
	// For database: typically same as CredentialBackend
	//
	// For the filesystem passwd backend this is the LEGACY flat key directory in
	// the read-only config tree; per-user keyrings now live under UserKeyringBase
	// (see below) and KeyBackend is only a read-fallback for unmigrated keys.
	KeyBackend string

	// UserKeyringBase is the parent directory of per-user data directories in the
	// writable data tree (i.e. the msgstore base path: {dataPath}/{domain}/users).
	// The filesystem passwd backend stores each user's keyring beside their
	// maildir at {UserKeyringBase}/{user}/keyring.{key,pub}, owned by the user's
	// uid -- so the delivery process (running as the recipient) can read its own
	// public key without config-tree access. Empty disables it (legacy KeyBackend
	// only).
	UserKeyringBase string

	// Options contains implementation-specific settings.
	Options map[string]string
}

var (
	authRegistryMu sync.RWMutex
	authRegistry   = make(map[string]AuthAgentFactory)
)

// RegisterAuthAgent adds an auth agent factory to the registry.
// It panics if called with an empty name or nil factory,
// or if the name is already registered.
func RegisterAuthAgent(name string, factory AuthAgentFactory) {
	if name == "" {
		panic("auth: RegisterAuthAgent called with empty name")
	}
	if factory == nil {
		panic("auth: RegisterAuthAgent called with nil factory")
	}

	authRegistryMu.Lock()
	defer authRegistryMu.Unlock()

	if _, exists := authRegistry[name]; exists {
		panic("auth: RegisterAuthAgent called twice for " + name)
	}
	authRegistry[name] = factory
}

// OpenAuthAgent creates an AuthenticationAgent using the registered factory for the config type.
func OpenAuthAgent(config AuthAgentConfig) (AuthenticationAgent, error) {
	authRegistryMu.RLock()
	factory, ok := authRegistry[config.Type]
	authRegistryMu.RUnlock()

	if !ok {
		return nil, errors.ErrAuthAgentNotRegistered
	}
	return factory(config)
}

// RegisteredAuthAgents returns a sorted list of registered auth agent type names.
func RegisteredAuthAgents() []string {
	authRegistryMu.RLock()
	defer authRegistryMu.RUnlock()

	types := make([]string, 0, len(authRegistry))
	for name := range authRegistry {
		types = append(types, name)
	}
	sort.Strings(types)
	return types
}
