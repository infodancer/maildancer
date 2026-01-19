package msgstore

import (
	"sort"
	"sync"

	"github.com/infodancer/maildancer/msgstore/errors"
)

// StoreFactory creates a MsgStore from configuration.
type StoreFactory func(config StoreConfig) (MsgStore, error)

// StoreConfig contains settings for opening a store.
type StoreConfig struct {
	// Type is the store type name (e.g., "maildir", "mbox").
	Type string

	// BasePath is the root directory for file-based stores.
	BasePath string

	// Options contains implementation-specific settings.
	Options map[string]string
}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]StoreFactory)
)

// Register adds a store factory to the registry.
// It panics if called with an empty name or nil factory,
// or if the name is already registered.
func Register(name string, factory StoreFactory) {
	if name == "" {
		panic("msgstore: Register called with empty name")
	}
	if factory == nil {
		panic("msgstore: Register called with nil factory")
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		panic("msgstore: Register called twice for " + name)
	}
	registry[name] = factory
}

// Open creates a MsgStore using the registered factory for the config type.
func Open(config StoreConfig) (MsgStore, error) {
	registryMu.RLock()
	factory, ok := registry[config.Type]
	registryMu.RUnlock()

	if !ok {
		return nil, errors.ErrStoreNotRegistered
	}
	return factory(config)
}

// RegisteredTypes returns a sorted list of registered store type names.
func RegisteredTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]string, 0, len(registry))
	for name := range registry {
		types = append(types, name)
	}
	sort.Strings(types)
	return types
}
