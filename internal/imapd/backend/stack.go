package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	msgstore "github.com/infodancer/maildancer/msgstore"
)

// StackConfig groups the configuration needed to build a Stack.
// TLSConfig is caller-supplied; tests may omit it (nil = plain IMAP only).
type StackConfig struct {
	Config    config.Config
	TLSConfig *tls.Config
	Collector metrics.Collector // nil → NoopCollector
	Logger    *slog.Logger      // nil → slog.Default()
}

// Stack owns all components of a running imapd instance and manages their lifecycle.
type Stack struct {
	srv       *imapserver.Server
	listeners []net.Listener
	closers   []io.Closer
	logger    *slog.Logger
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
		logger.Info("domain provider enabled", "path", cfg.Config.DomainsPath, "data_path", cfg.Config.DomainsDataPath)
	}

	// Create auth router (centralizes domain-aware auth routing).
	authRouter := domain.NewAuthRouter(domainProvider, authAgent)

	// Open message store if configured.
	var store msgstore.MsgStore
	if cfg.Config.Store.Type != "" {
		var err error
		store, err = msgstore.Open(msgstore.StoreConfig{
			Type:     cfg.Config.Store.Type,
			BasePath: cfg.Config.Store.BasePath,
			Options:  cfg.Config.Store.Options,
		})
		if err != nil {
			s.Close() //nolint:errcheck
			return nil, err
		}
		if c, ok := store.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}
		logger.Info("message store opened", "type", cfg.Config.Store.Type)
	}

	// Create IMAP server.
	opts := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			collector.ConnectionOpened()
			session := NewSession(conn, &cfg.Config, authRouter, store, collector, logger)
			return session, &imapserver.GreetingData{}, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapMove: {}},
		TLSConfig:    cfg.TLSConfig,
		InsecureAuth: cfg.TLSConfig == nil,
	}
	if cfg.Config.LogLevel == "debug" {
		opts.DebugWriter = os.Stderr
	}
	srv := imapserver.New(opts)
	s.srv = srv

	// Create listeners for each configured address.
	for _, lc := range cfg.Config.Listeners {
		var ln net.Listener
		var err error
		switch lc.Mode {
		case config.ModeImaps:
			if cfg.TLSConfig == nil {
				s.Close() //nolint:errcheck
				return nil, errors.New("listener " + lc.Address + " requires TLS but no TLS config provided")
			}
			ln, err = tls.Listen("tcp", lc.Address, cfg.TLSConfig)
		default: // ModeImap
			ln, err = net.Listen("tcp", lc.Address)
		}
		if err != nil {
			s.Close() //nolint:errcheck
			return nil, err
		}
		s.listeners = append(s.listeners, ln)
		s.closers = append(s.closers, ln)
		logger.Info("listening", "address", lc.Address, "mode", string(lc.Mode))
	}

	return s, nil
}

// Run starts serving on all listeners and blocks until ctx is cancelled.
func (s *Stack) Run(ctx context.Context) error {
	for _, ln := range s.listeners {
		ln := ln
		go func() {
			if err := s.srv.Serve(ln); err != nil {
				s.logger.Error("server error", "error", err)
			}
		}()
	}
	<-ctx.Done()
	_ = s.srv.Close()
	return nil
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
