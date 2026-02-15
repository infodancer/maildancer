package domain

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
)

// FilesystemDomainProvider loads domain configs from a directory structure.
// Each domain has its own subdirectory containing a config.toml file.
//
// Directory structure:
//
//	/etc/mail/domains/
//	├── example.com/
//	│   └── config.toml
//	├── other.org/
//	│   └── config.toml
type FilesystemDomainProvider struct {
	basePath string
	cache    map[string]*Domain
	mu       sync.RWMutex
	logger   *slog.Logger
}

// NewFilesystemDomainProvider creates a new filesystem-based domain provider.
func NewFilesystemDomainProvider(basePath string, logger *slog.Logger) *FilesystemDomainProvider {
	if logger == nil {
		logger = slog.Default()
	}
	return &FilesystemDomainProvider{
		basePath: basePath,
		cache:    make(map[string]*Domain),
		logger:   logger,
	}
}

// GetDomain returns the Domain for a given domain name.
// Returns nil if the domain is not handled.
func (p *FilesystemDomainProvider) GetDomain(name string) *Domain {
	name = strings.ToLower(name)

	// Check cache first
	p.mu.RLock()
	if domain, ok := p.cache[name]; ok {
		p.mu.RUnlock()
		return domain
	}
	p.mu.RUnlock()

	// Check if domain directory exists
	domainPath := filepath.Join(p.basePath, name)
	configPath := filepath.Join(domainPath, "config.toml")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil // Domain not handled
	}

	// Load config and create Domain
	domain, err := p.loadDomain(name, domainPath, configPath)
	if err != nil {
		p.logger.Error("failed to load domain",
			slog.String("domain", name),
			slog.String("error", err.Error()))
		return nil
	}

	// Cache for future use
	p.mu.Lock()
	// Double-check in case another goroutine loaded it
	if existing, ok := p.cache[name]; ok {
		p.mu.Unlock()
		// Clean up the one we just created
		_ = domain.Close()
		return existing
	}
	p.cache[name] = domain
	p.mu.Unlock()

	return domain
}

// loadDomain loads a domain configuration and creates the domain agents.
func (p *FilesystemDomainProvider) loadDomain(name, domainPath, configPath string) (*Domain, error) {
	// Load config.toml
	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Create auth agent (paths relative to domainPath)
	authCfg := auth.AuthAgentConfig{
		Type:              cfg.Auth.Type,
		CredentialBackend: filepath.Join(domainPath, cfg.Auth.CredentialBackend),
		KeyBackend:        filepath.Join(domainPath, cfg.Auth.KeyBackend),
		Options:           cfg.Auth.Options,
	}
	authAgent, err := auth.OpenAuthAgent(authCfg)
	if err != nil {
		return nil, fmt.Errorf("create auth agent: %w", err)
	}

	// Create message store (paths relative to domainPath)
	storeCfg := msgstore.StoreConfig{
		Type:     cfg.MsgStore.Type,
		BasePath: filepath.Join(domainPath, cfg.MsgStore.BasePath),
		Options:  cfg.MsgStore.Options,
	}
	store, err := msgstore.Open(storeCfg)
	if err != nil {
		_ = authAgent.Close()
		return nil, fmt.Errorf("create msgstore: %w", err)
	}

	p.logger.Debug("loaded domain",
		slog.String("domain", name),
		slog.String("auth_type", cfg.Auth.Type),
		slog.String("store_type", cfg.MsgStore.Type))

	return &Domain{
		Name:          name,
		AuthAgent:     authAgent,
		DeliveryAgent: store,
		MessageStore:  store,
	}, nil
}

// Domains returns the list of domain names handled by this provider.
func (p *FilesystemDomainProvider) Domains() []string {
	entries, err := os.ReadDir(p.basePath)
	if err != nil {
		p.logger.Debug("failed to read domains directory",
			slog.String("path", p.basePath),
			slog.String("error", err.Error()))
		return nil
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			configPath := filepath.Join(p.basePath, entry.Name(), "config.toml")
			if _, err := os.Stat(configPath); err == nil {
				domains = append(domains, entry.Name())
			}
		}
	}
	return domains
}

// Close releases resources for all loaded domains.
func (p *FilesystemDomainProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	for name, domain := range p.cache {
		if err := domain.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close domain %s: %w", name, err))
		}
	}
	p.cache = make(map[string]*Domain)
	return errors.Join(errs...)
}
