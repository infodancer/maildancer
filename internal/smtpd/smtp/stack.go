package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"path/filepath"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// Stack owns all components of a running smtpd instance and manages their lifecycle.
type Stack struct {
	Server  *Server
	closers []io.Closer
	logger  *slog.Logger
}

// StackConfig groups config needed to build a Stack.
// TLSConfig and SpamChecker are caller-supplied (main.go builds them; tests omit them).
type StackConfig struct {
	Config      config.Config
	TLSConfig   *tls.Config
	SpamChecker spamcheck.Checker
	SpamConfig  config.SpamCheckConfig
	Collector   metrics.Collector // nil → NoopCollector
	Logger      *slog.Logger      // nil → slog.Default()
}

// NewStack creates a Stack from the given configuration, wiring up all components.
func NewStack(cfg StackConfig) (*Stack, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	collector := cfg.Collector
	if collector == nil {
		collector = &metrics.NoopCollector{}
	}

	s := &Stack{logger: logger}

	// Create authentication agent if configured.
	var authAgent auth.AuthenticationAgent
	if cfg.Config.Auth.IsEnabled() {
		agentConfig := auth.AuthAgentConfig{
			Type:              cfg.Config.Auth.AgentType,
			CredentialBackend: cfg.Config.Auth.CredentialBackend,
			KeyBackend:        cfg.Config.Auth.KeyBackend,
			Options:           cfg.Config.Auth.Options,
		}
		var err error
		authAgent, err = auth.OpenAuthAgent(agentConfig)
		if err != nil {
			return nil, err
		}
		s.closers = append(s.closers, authAgent)
		logger.Info("authentication enabled", "type", cfg.Config.Auth.AgentType)
	}

	// Create delivery agent if configured.
	var delivery msgstore.DeliveryAgent
	if cfg.Config.Delivery.Type != "" {
		storeConfig := msgstore.StoreConfig{
			Type:     cfg.Config.Delivery.Type,
			BasePath: cfg.Config.Delivery.BasePath,
			Options:  cfg.Config.Delivery.Options,
		}
		store, err := msgstore.Open(storeConfig)
		if err != nil {
			s.Close() //nolint:errcheck
			return nil, err
		}
		delivery = store
		logger.Info("delivery enabled", "type", cfg.Config.Delivery.Type, "path", cfg.Config.Delivery.BasePath)
	}

	// Create domain provider if configured.
	var domainProvider domain.DomainProvider
	if cfg.Config.DomainsPath != "" {
		dp := domain.NewFilesystemDomainProvider(cfg.Config.DomainsPath, logger)
		if cfg.Config.DomainsDataPath != "" {
			dp = dp.WithDataPath(cfg.Config.DomainsDataPath)
		}
		domainProvider = dp.WithDefaults(domain.DomainConfig{
			Auth: domain.DomainAuthConfig{
				Type:              "passwd",
				CredentialBackend: "passwd",
				KeyBackend:        "keys",
			},
			MsgStore: domain.DomainMsgStoreConfig{
				Type:     "maildir",
				BasePath: "users",
			},
		})
		s.closers = append(s.closers, domainProvider)
		logger.Info("domain provider enabled", "path", cfg.Config.DomainsPath)
	}

	// Create auth router (centralizes domain-aware auth routing).
	authRouter := domain.NewAuthRouter(domainProvider, authAgent)

	// Build temp dir path: on the same filesystem as the mail store so
	// temp files can be renamed atomically into the maildir.
	var tempDir string
	if cfg.Config.Delivery.BasePath != "" {
		tempDir = filepath.Join(cfg.Config.Delivery.BasePath, "tmp")
	}

	backend := NewBackend(BackendConfig{
		Hostname:       cfg.Config.Hostname,
		Delivery:       delivery,
		AuthAgent:      authAgent,
		AuthRouter:     authRouter,
		DomainProvider: domainProvider,
		SpamChecker:    cfg.SpamChecker,
		SpamConfig:     cfg.SpamConfig,
		Collector:      collector,
		MaxRecipients:  cfg.Config.Limits.MaxRecipients,
		MaxMessageSize: int64(cfg.Config.Limits.MaxMessageSize),
		TempDir:        tempDir,
		Logger:         logger,
	})

	srv, err := NewServer(ServerConfig{
		Backend:        backend,
		Listeners:      cfg.Config.Listeners,
		Hostname:       cfg.Config.Hostname,
		TLSConfig:      cfg.TLSConfig,
		ReadTimeout:    cfg.Config.Timeouts.ConnectionTimeout(),
		WriteTimeout:   cfg.Config.Timeouts.ConnectionTimeout(),
		MaxMessageSize: cfg.Config.Limits.MaxMessageSize,
		MaxRecipients:  cfg.Config.Limits.MaxRecipients,
		Logger:         logger,
	})
	if err != nil {
		s.Close() //nolint:errcheck
		return nil, err
	}

	s.Server = srv
	return s, nil
}

// Run starts the server and blocks until the context is cancelled.
func (s *Stack) Run(ctx context.Context) error {
	return s.Server.Run(ctx)
}

// Close shuts down all closeable components in reverse registration order.
func (s *Stack) Close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
