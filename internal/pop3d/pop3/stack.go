package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

// StackConfig groups the configuration needed to build a Stack.
// TLSConfig is caller-supplied; tests may omit it (nil = plain POP3 only).
type StackConfig struct {
	Config    config.Config
	TLSConfig *tls.Config
	MsgStore  msgstore.MessageStore // overrides config.Maildir when non-nil
	Collector metrics.Collector     // nil → NoopCollector
	Logger    *slog.Logger          // nil → slog.Default()
}

// Stack owns all components of a running pop3d instance and manages their lifecycle.
type Stack struct {
	server  *server.Server
	closers []io.Closer
	logger  *slog.Logger
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
	if cfg.Config.Auth.IsConfigured() {
		agentConfig := auth.AuthAgentConfig{
			Type:              cfg.Config.Auth.Type,
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
		logger.Info("authentication enabled", "type", cfg.Config.Auth.Type)
	}

	// Create message store: caller-supplied store takes priority over config.
	var msgStore msgstore.MessageStore
	if cfg.MsgStore != nil {
		msgStore = cfg.MsgStore
		logger.Info("message store enabled", "type", "caller-supplied")
	} else if cfg.Config.Maildir != "" {
		store, err := msgstore.Open(msgstore.StoreConfig{
			Type:     "maildir",
			BasePath: cfg.Config.Maildir,
		})
		if err != nil {
			s.Close() //nolint:errcheck
			return nil, err
		}
		msgStore = store
		if c, ok := store.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}
		logger.Info("message store enabled", "type", "maildir", "path", cfg.Config.Maildir)
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

	// Create server.
	srv, err := server.New(server.Config{
		Cfg:       &cfg.Config,
		TLSConfig: cfg.TLSConfig,
		Logger:    logger,
	})
	if err != nil {
		s.Close() //nolint:errcheck
		return nil, err
	}

	// Set POP3 protocol handler.
	handler := Handler(cfg.Config.Hostname, authRouter, msgStore, cfg.TLSConfig, collector)
	srv.SetHandler(handler)

	s.server = srv
	return s, nil
}

// Run starts the server and blocks until the context is cancelled.
func (s *Stack) Run(ctx context.Context) error {
	return s.server.Run(ctx)
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

// RunSingleConn processes exactly one POP3 session on the given connection.
// For POP3S mode, the connection is wrapped with TLS before the session starts.
func (s *Stack) RunSingleConn(conn net.Conn, mode config.ListenerMode, tlsConfig *tls.Config) error {
	cfg := s.server.Config()
	connCfg := server.ConnectionConfig{
		IdleTimeout:    cfg.Timeouts.ConnectionTimeout(),
		CommandTimeout: cfg.Timeouts.CommandTimeout(),
		LogTransaction: cfg.LogLevel == "debug",
		Logger:         s.logger,
	}
	c := server.NewConnection(conn, connCfg)
	if mode == config.ModePop3s {
		if tlsConfig == nil {
			return fmt.Errorf("POP3S mode requires TLS configuration")
		}
		if err := c.UpgradeToTLS(tlsConfig); err != nil {
			return fmt.Errorf("TLS upgrade: %w", err)
		}
	}
	ctx := context.Background()
	handler := s.server.Handler()
	if handler == nil {
		return fmt.Errorf("no handler configured on server")
	}
	handler(ctx, c)
	return nil
}
