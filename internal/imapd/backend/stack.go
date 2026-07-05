package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/imapd/notify"
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

	// Session-manager is required.
	if !cfg.Config.SessionManager.IsEnabled() {
		return nil, fmt.Errorf("session-manager configuration is required")
	}

	// Adjust dangerous timer combinations before any sessions are created.
	cfg.Config.Timeouts.NormalizeSessionKeepalive(logger)

	// Create Redis subscriber for IDLE notifications.
	var subscriber *notify.Subscriber
	if cfg.Config.Redis.URL != "" {
		var err error
		subscriber, err = notify.NewSubscriber(cfg.Config.Redis.URL, cfg.Config.Redis.Password, logger)
		if err != nil {
			s.Close() //nolint:errcheck
			return nil, err
		}
		s.closers = append(s.closers, subscriber)
		logger.Info("redis subscriber enabled", "url", cfg.Config.Redis.URL)
	}

	// Create session-manager client.
	smClient, err := NewSessionManagerClient(cfg.Config.SessionManager, logger)
	if err != nil {
		s.Close() //nolint:errcheck
		return nil, err
	}
	s.closers = append(s.closers, smClient)
	logger.Info("session-manager client enabled",
		"socket", cfg.Config.SessionManager.Socket,
		"address", cfg.Config.SessionManager.Address,
	)

	// Create IMAP server.
	opts := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			collector.ConnectionOpened()
			session := NewSession(conn, &cfg.Config, smClient, subscriber, collector, logger)
			return session, &imapserver.GreetingData{}, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapMove: {}},
		TLSConfig:    cfg.TLSConfig,
		InsecureAuth: cfg.TLSConfig == nil,
		// Route go-imap's internal error sink (panics, session/greeting
		// failures, and the "handling <CMD> command" errors it turns into
		// "NO [SERVERBUG]") through slog at error level. Left nil, go-imap
		// falls back to log.Default() and those faults bypass structured
		// logging entirely. See issue #131.
		Logger: logging.NewStdLogger(logger.With("component", "imapd")),
	}
	if cfg.Config.LogLevel == "debug" {
		opts.DebugWriter = logging.DebugWriter(logger, "imap-protocol")
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
