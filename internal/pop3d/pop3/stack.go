package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

// StackConfig groups the configuration needed to build a Stack.
// TLSConfig is caller-supplied; tests may omit it (nil = plain POP3 only).
type StackConfig struct {
	Config    config.Config
	TLSConfig *tls.Config
	Collector metrics.Collector // nil → NoopCollector
	Logger    *slog.Logger      // nil → slog.Default()
}

// Stack owns all components of a running pop3d instance and manages their lifecycle.
type Stack struct {
	server  *server.Server
	closers []io.Closer
	logger  *slog.Logger
}

// NewStack creates a Stack from the given configuration, wiring up all components.
// Session-manager is required -- pop3d delegates all authentication and mailbox
// operations to it.
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

	smClient, err := NewSessionManagerClient(cfg.Config.SessionManager, logger)
	if err != nil {
		return nil, fmt.Errorf("session-manager: %w", err)
	}
	s.closers = append(s.closers, smClient)
	logger.Info("session-manager enabled",
		"socket", cfg.Config.SessionManager.Socket,
		"address", cfg.Config.SessionManager.Address)

	// Create server.
	srv, err := server.New(server.Config{
		Cfg:       &cfg.Config,
		TLSConfig: cfg.TLSConfig,
		Logger:    logger,
	})
	if err != nil {
		s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
		return nil, err
	}

	// Set POP3 protocol handler.
	handler := Handler(cfg.Config.Hostname, smClient, cfg.TLSConfig, collector)
	srv.SetHandler(handler)

	s.server = srv
	return s, nil
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

// RunSingleConn processes exactly one POP3 session on the given connection --
// the code path the protocol-handler subprocess runs (mail-security-model.md,
// #179). For POP3S mode, the connection is wrapped with the stack's TLS
// configuration before the session starts. It applies the same session guards
// the goroutine listener path had: idle-timeout enforcement and panic
// recovery (#137) -- without them an idle or crashed session would pin the
// handler process (and its dispatcher connection slot) indefinitely.
func (s *Stack) RunSingleConn(conn net.Conn, mode config.ListenerMode) (err error) {
	cfg := s.server.Config()
	connCfg := server.ConnectionConfig{
		IdleTimeout:    cfg.Timeouts.ConnectionTimeout(),
		CommandTimeout: cfg.Timeouts.CommandTimeout(),
		LogTransaction: cfg.LogLevel == "debug",
		Logger:         s.logger,
	}
	c := server.NewConnection(conn, connCfg)
	logger := c.Logger()

	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic serving connection",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			_ = c.Close()
			err = fmt.Errorf("panic serving connection: %v", r)
		}
	}()

	if mode == config.ModePop3s {
		tlsConfig := s.server.TLSConfig()
		if tlsConfig == nil {
			return fmt.Errorf("POP3S mode requires TLS configuration")
		}
		if err := c.UpgradeToTLS(tlsConfig); err != nil {
			return fmt.Errorf("TLS upgrade: %w", err)
		}
	}

	handler := s.server.Handler()
	if handler == nil {
		return fmt.Errorf("no handler configured on server")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = logging.NewContext(ctx, logger)

	if err := c.ResetIdleTimeout(); err != nil {
		_ = c.Close()
		return fmt.Errorf("set initial timeout: %w", err)
	}

	// The idle monitor runs in its own goroutine, so it needs its own panic
	// guard; on panic, cancel the session context rather than crash without
	// the structured log.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic in idle monitor",
					slog.Any("panic", r),
					slog.String("stack", string(debug.Stack())),
				)
				cancel()
			}
		}()
		c.IdleMonitor(ctx)
	}()

	handler(ctx, c)
	_ = c.Close()
	return nil
}
