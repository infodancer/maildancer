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
	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/msgstore"
)

// FilesystemDomainProvider loads domain configs from a directory structure.
// Each domain has its own subdirectory. A per-domain config.toml is optional
// when defaults are set via WithDefaults — any subdirectory is then a valid
// domain, with config.toml values overriding the defaults when present.
//
// A config.toml at the basePath level (alongside domain directories) provides
// provider-level defaults, including a [forwards] section for the system-wide
// default forwarding rules.
//
// Directory structure:
//
//	/etc/mail/domains/
//	├── config.toml       (optional; provider-level defaults incl. [forwards])
//	├── example.com/
//	│   └── config.toml   (optional when defaults are set)
//	├── other.org/
//	│   └── config.toml
type FilesystemDomainProvider struct {
	basePath     string
	defaults     *DomainConfig
	baseDefaults *DomainConfig // loaded from {basePath}/config.toml
	cache        map[string]*Domain
	mu           sync.RWMutex
	logger       *slog.Logger
}

// NewFilesystemDomainProvider creates a new filesystem-based domain provider.
// If {basePath}/config.toml exists, it is loaded as provider-level defaults
// (used for [forwards] and other domain-wide settings).
func NewFilesystemDomainProvider(basePath string, logger *slog.Logger) *FilesystemDomainProvider {
	if logger == nil {
		logger = slog.Default()
	}
	p := &FilesystemDomainProvider{
		basePath: basePath,
		cache:    make(map[string]*Domain),
		logger:   logger,
	}
	if baseCfg, err := LoadDomainConfig(filepath.Join(basePath, "config.toml")); err == nil {
		p.baseDefaults = baseCfg
	}
	return p
}

// WithDefaults sets default domain configuration values used when a domain
// directory has no config.toml, or to fill in fields not present in it.
// Returns the provider to allow chaining.
func (p *FilesystemDomainProvider) WithDefaults(cfg DomainConfig) *FilesystemDomainProvider {
	p.defaults = &cfg
	return p
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

	if p.defaults != nil {
		// With defaults: domain directory must exist; config.toml is optional
		if _, err := os.Stat(domainPath); os.IsNotExist(err) {
			return nil
		}
	} else {
		// Without defaults: config.toml is required
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return nil
		}
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
// If defaults are set, they serve as the base; per-domain config.toml overrides them.
func (p *FilesystemDomainProvider) loadDomain(name, domainPath, configPath string) (*Domain, error) {
	var cfg *DomainConfig

	// Start with defaults if set
	if p.defaults != nil {
		base := *p.defaults
		cfg = &base
	}

	// Load per-domain config.toml if it exists, merging on top of defaults.
	// Capture the raw override before merging so we can inspect Forwards separately.
	var domainOverride *DomainConfig
	if _, err := os.Stat(configPath); err == nil {
		override, err := LoadDomainConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		domainOverride = override
		if cfg != nil {
			merged := mergeConfig(*cfg, *override)
			cfg = &merged
		} else {
			cfg = override
		}
	} else if cfg == nil {
		return nil, fmt.Errorf("no config.toml and no defaults set for domain %s", name)
	}

	// Create auth agent (absolute paths used as-is, relative paths joined with domainPath)
	authCfg := auth.AuthAgentConfig{
		Type:              cfg.Auth.Type,
		CredentialBackend: resolvePath(domainPath, cfg.Auth.CredentialBackend),
		KeyBackend:        resolvePath(domainPath, cfg.Auth.KeyBackend),
		Options:           cfg.Auth.Options,
	}
	authAgent, err := auth.OpenAuthAgent(authCfg)
	if err != nil {
		return nil, fmt.Errorf("create auth agent: %w", err)
	}

	// Create message store (absolute paths used as-is, relative paths joined with domainPath)
	storeCfg := msgstore.StoreConfig{
		Type:     cfg.MsgStore.Type,
		BasePath: resolvePath(domainPath, cfg.MsgStore.BasePath),
		Options:  cfg.MsgStore.Options,
	}
	store, err := msgstore.Open(storeCfg)
	if err != nil {
		_ = authAgent.Close()
		return nil, fmt.Errorf("create msgstore: %w", err)
	}

	// Build forwarding chain from [forwards] sections in config.toml files.
	//
	// Resolution order:
	//   1. User-level:   {domainPath}/user_forwards/{localpart}  (read on demand, deferred)
	//   2. Domain-level: per-domain config.toml [forwards]       (loaded now)
	//   3. System default: {basePath}/config.toml [forwards]     (loaded now)
	//
	// If the domain's config.toml has a [forwards] section (even empty), it takes
	// full ownership: the system default is suppressed. This lets a domain admin
	// disable the global catchall by setting forwards = {}.
	var domainFwd, defaultFwd *forwards.ForwardMap
	if domainOverride != nil && domainOverride.Forwards != nil {
		// Domain explicitly declared [forwards] — use it, suppress system default.
		domainFwd = forwards.FromMap(domainOverride.Forwards)
		defaultFwd = forwards.FromMap(nil)
	} else {
		// Domain did not declare [forwards] — fall through to system default.
		domainFwd = forwards.FromMap(nil)
		if p.baseDefaults != nil {
			defaultFwd = forwards.FromMap(p.baseDefaults.Forwards)
		} else {
			defaultFwd = forwards.FromMap(nil)
		}
	}

	chain := &forwardChain{
		userForwardsDir: filepath.Join(domainPath, "user_forwards"),
		domainForwards:  domainFwd,
		defaultForwards: defaultFwd,
	}

	// Wrap auth agent so UserExists returns true for forward-only addresses.
	finalAuth := &mailAuthAgent{
		inner: authAgent,
		chain: chain,
	}

	// Wrap delivery agent to expand forwarding rules at delivery time.
	var finalDelivery msgstore.DeliveryAgent = &MailDeliveryAgent{
		inner:    store,
		chain:    chain,
		provider: p,
	}

	p.logger.Debug("loaded domain",
		slog.String("domain", name),
		slog.String("auth_type", cfg.Auth.Type),
		slog.String("store_type", cfg.MsgStore.Type))

	return &Domain{
		Name:          name,
		AuthAgent:     finalAuth,
		DeliveryAgent: finalDelivery,
		MessageStore:  store,
	}, nil
}

// Domains returns the list of domain names handled by this provider.
// When defaults are set, all subdirectories are considered valid domains.
// Without defaults, only subdirectories containing a config.toml are listed.
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
		if !entry.IsDir() {
			continue
		}
		if p.defaults != nil {
			// With defaults: any subdirectory is a valid domain
			domains = append(domains, entry.Name())
		} else {
			// Without defaults: only directories with config.toml
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

// resolvePath returns path as-is if absolute, or joined with base if relative.
func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
