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
// when defaults are set via WithDefaults -- any subdirectory is then a valid
// domain, with config.toml values overriding the defaults when present.
//
// Additional config files at the basePath level:
//
//   - config.toml  -- system-wide defaults (forwards, auth type, etc.)
//   - domains.toml -- per-domain behavior overrides managed by the system postmaster
//   - postmaster   -- authoritative domain GIDs, postmaster UIDs, and data paths
//
// Directory structure:
//
//	/etc/mail/domains/
//	├── config.toml       (optional; system-wide defaults incl. [forwards])
//	├── domains.toml      (optional; per-domain overrides with ["example.com"] sections)
//	├── postmaster        (optional; address:uid:gid:data-path entries)
//	├── example.com/
//	│   └── config.toml   (optional when defaults are set; domain-admin editable)
//	├── other.org/
//	│   └── config.toml
type FilesystemDomainProvider struct {
	basePath        string
	dataPath        string // provider-level data directory (overridden per-domain by postmaster)
	defaults        *DomainConfig
	baseDefaults    *DomainConfig               // loaded from {basePath}/config.toml
	domainOverrides DomainsConfig               // loaded from {basePath}/domains.toml
	postmaster      map[string]*PostmasterEntry // loaded from {basePath}/postmaster
	cache           map[string]*Domain
	mu              sync.RWMutex
	logger          *slog.Logger
}

// NewFilesystemDomainProvider creates a new filesystem-based domain provider.
// Loads optional config files from basePath: config.toml (system-wide defaults),
// domains.toml (per-domain behavior overrides), and postmaster (domain GIDs and paths).
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
	if overrides, err := LoadDomainsConfig(filepath.Join(basePath, "domains.toml")); err == nil {
		p.domainOverrides = overrides
	}
	if entries, err := ParsePostmasterFile(filepath.Join(basePath, "postmaster")); err == nil {
		p.postmaster = entries
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

// WithDataPath sets a separate base directory for resolving msgstore paths.
// When set, relative MsgStore.BasePath values are joined with {dataPath}/{domain}
// rather than the domain's config directory. This separates read-only config
// (under basePath) from writable message storage (under dataPath).
func (p *FilesystemDomainProvider) WithDataPath(path string) *FilesystemDomainProvider {
	p.dataPath = path
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
// Config is merged in priority order (lowest to highest):
//  1. Programmatic defaults (WithDefaults)
//  2. System config.toml ({basePath}/config.toml)
//  3. domains.toml per-domain overrides
//  4. Per-domain config.toml
//  5. Postmaster GID (authoritative, applied post-merge)
func (p *FilesystemDomainProvider) loadDomain(name, domainPath, configPath string) (*Domain, error) {
	// Build config layers (lowest to highest priority).
	var layers []map[string]any

	// 1. Programmatic defaults (from WithDefaults).
	if p.defaults != nil {
		m, err := toTOMLMap(*p.defaults)
		if err != nil {
			return nil, fmt.Errorf("marshal defaults: %w", err)
		}
		layers = append(layers, m)
	}

	// 2. System config.toml ({basePath}/config.toml).
	if p.baseDefaults != nil {
		m, err := toTOMLMap(*p.baseDefaults)
		if err != nil {
			return nil, fmt.Errorf("marshal base defaults: %w", err)
		}
		layers = append(layers, m)
	}

	// 3. domains.toml per-domain overrides.
	if override, ok := p.domainOverrides[name]; ok {
		m, err := toTOMLMap(override)
		if err != nil {
			return nil, fmt.Errorf("marshal domain overrides: %w", err)
		}
		layers = append(layers, m)
	}

	// 4. Per-domain config.toml (highest priority for config values).
	var perDomainMap map[string]any
	if _, err := os.Stat(configPath); err == nil {
		m, err := loadTOMLMap(configPath)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		perDomainMap = m
		layers = append(layers, m)
	} else if p.defaults == nil {
		return nil, fmt.Errorf("no config.toml and no defaults set for domain %s", name)
	}

	// Merge all layers into final config.
	var cfg DomainConfig
	if err := mergeConfigLayers(&cfg, layers...); err != nil {
		return nil, fmt.Errorf("merge config: %w", err)
	}

	// Postmaster GID is authoritative -- applied after all config merges so that
	// neither system defaults nor domain-admin config.toml can override it.
	if p.postmaster != nil {
		if entry, ok := p.postmaster[name]; ok && entry.GID != 0 {
			cfg.Gid = entry.GID
		}
	}

	// Resolve the writable storage base first. The data path comes from
	// (highest priority first):
	//   1. postmaster file DataPath for this domain
	//   2. provider-level WithDataPath() joined with domain name
	//   3. the domain's config directory
	storageBase := domainPath
	if p.postmaster != nil {
		if entry, ok := p.postmaster[name]; ok && entry.DataPath != "" {
			storageBase = entry.DataPath
		} else if p.dataPath != "" {
			storageBase = filepath.Join(p.dataPath, name)
		}
	} else if p.dataPath != "" {
		storageBase = filepath.Join(p.dataPath, name)
	}
	// The per-user data directory parent ({dataPath}/{domain}/users). Per-user
	// keyrings live here (beside the maildir), so the delivery process can read
	// its own public key as the recipient uid -- no config-tree access needed.
	userStoreBase := resolvePath(storageBase, cfg.MsgStore.BasePath)

	// Create lazy auth agent -- defers OpenAuthAgent() until the first
	// auth-related call (Authenticate, UserExists, etc.). This allows
	// privilege-dropped processes (e.g., mail-session oneshot delivery)
	// to use GetDomain() for forwarding/spam/sieve without needing read
	// access to credential files.
	authAgent := &lazyAuthAgent{
		cfg: auth.AuthAgentConfig{
			Type:              cfg.Auth.Type,
			CredentialBackend: resolvePath(domainPath, cfg.Auth.CredentialBackend),
			KeyBackend:        resolvePath(domainPath, cfg.Auth.KeyBackend),
			UserKeyringBase:   userStoreBase,
			Options:           cfg.Auth.Options,
		},
	}

	storeCfg := msgstore.StoreConfig{
		Type:     cfg.MsgStore.Type,
		BasePath: userStoreBase,
		Options:  cfg.MsgStore.Options,
	}
	store, err := msgstore.Open(storeCfg)
	if err != nil {
		_ = authAgent.Close()
		return nil, fmt.Errorf("create msgstore: %w", err)
	}

	// Build the forwarding chain. Resolution order (admins/domains win over
	// users -- see forwardChain doc):
	//   1. Admin override: per-domain config.toml [forwards]       (loaded now)
	//   2. Domain:         {domainPath}/forwards file              (loaded now)
	//   3. User:           {domainPath}/user_forwards/{localpart}  (read on demand)
	//   4. System default: {basePath}/config.toml [forwards]       (loaded now)
	//
	// If the domain's config.toml has a [forwards] section (even empty), the
	// admin tier takes full ownership and the system default is suppressed. This
	// lets a domain admin disable the global catchall by setting forwards = {}.
	var adminFwd, defaultFwd *forwards.ForwardMap
	if perDomainMap != nil && perDomainMap["forwards"] != nil {
		// Domain explicitly declared [forwards] -- use it, suppress system default.
		adminFwd = forwards.FromMap(cfg.Forwards)
		defaultFwd = forwards.FromMap(nil)
	} else {
		// Domain did not declare [forwards] -- fall through to system default.
		adminFwd = forwards.FromMap(nil)
		if p.baseDefaults != nil {
			defaultFwd = forwards.FromMap(p.baseDefaults.Forwards)
		} else {
			defaultFwd = forwards.FromMap(nil)
		}
	}

	// Domain tier: the per-domain `forwards` file. A missing file is empty (not
	// an error); a malformed file degrades to an empty tier rather than failing
	// the whole domain load.
	domainFwd, err := forwards.Load(filepath.Join(domainPath, "forwards"))
	if err != nil {
		p.logger.Warn("load domain forwards file",
			slog.String("domain", name),
			slog.String("error", err.Error()))
		domainFwd = forwards.FromMap(nil)
	}

	chain := &forwardChain{
		adminForwards:   adminFwd,
		domainForwards:  domainFwd,
		userForwardsDir: filepath.Join(domainPath, "user_forwards"),
		defaultForwards: defaultFwd,
	}

	// Wrap auth agent so UserExists returns true for forward-only addresses.
	finalAuth := &mailAuthAgent{
		inner: authAgent,
		chain: chain,
	}

	// Wrap delivery agent as an extension seam for future per-domain delivery
	// behavior. Forwarding is resolved upstream in session-manager, before the
	// privilege drop -- this agent only performs local mailbox writes.
	var finalDelivery msgstore.DeliveryAgent = &MailDeliveryAgent{
		inner: store,
	}

	p.logger.Debug("loaded domain",
		slog.String("domain", name),
		slog.String("auth_type", cfg.Auth.Type),
		slog.String("store_type", cfg.MsgStore.Type))

	dom := &Domain{
		Name:               name,
		AuthAgent:          finalAuth,
		DeliveryAgent:      finalDelivery,
		MessageStore:       store,
		MaxMessageSize:     cfg.MaxMessageSize,
		RecipientRejection: cfg.RecipientRejection,
		Limits:             cfg.Limits,
	}

	// Load DKIM signing key if configured.
	if cfg.DKIM.Selector != "" && cfg.DKIM.PrivateKeyPath != "" {
		keyPath := resolvePath(domainPath, cfg.DKIM.PrivateKeyPath)
		key, err := LoadDKIMKey(keyPath)
		if err != nil {
			p.logger.Warn("failed to load DKIM key",
				slog.String("domain", name),
				slog.String("path", keyPath),
				slog.String("error", err.Error()))
		} else {
			dom.DKIMSelector = cfg.DKIM.Selector
			dom.DKIMKey = key
			p.logger.Info("DKIM signing enabled",
				slog.String("domain", name),
				slog.String("selector", cfg.DKIM.Selector))
		}
	}

	return dom, nil
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
