package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
)

// Server coordinates multiple listeners and handles POP3 connections.
type Server struct {
	cfg       *config.Config
	tlsConfig *tls.Config
	logger    *slog.Logger
	handler   ConnectionHandler

	listeners []*Listener
	mu        sync.Mutex
}

// Config holds configuration for creating a new Server.
type Config struct {
	Cfg       *config.Config
	TLSConfig *tls.Config
	Logger    *slog.Logger
}

// New creates a new Server with the given configuration.
func New(sc Config) (*Server, error) {
	logger := sc.Logger
	if logger == nil {
		logger = logging.NewLogger(sc.Cfg.LogLevel)
	}

	s := &Server{
		cfg:       sc.Cfg,
		tlsConfig: sc.TLSConfig,
		logger:    logger,
	}

	return s, nil
}

// SetHandler sets the connection handler for all listeners.
// Must be called before Run.
func (s *Server) SetHandler(handler ConnectionHandler) {
	s.handler = handler
}

// Run starts all configured listeners and blocks until the context is cancelled.
// All listeners run in their own goroutines.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()

	if s.handler == nil {
		s.handler = s.defaultHandler
	}

	// Create listeners
	for _, lc := range s.cfg.Listeners {
		// Determine if this listener needs TLS
		var tlsCfg *tls.Config
		if lc.Mode == config.ModePop3s {
			if s.tlsConfig == nil {
				s.mu.Unlock()
				return fmt.Errorf("listener %s: TLS required for POP3S mode but not configured", lc.Address)
			}
			tlsCfg = s.tlsConfig
		} else if s.tlsConfig != nil {
			// Make TLS available for STLS on non-POP3S listeners
			tlsCfg = s.tlsConfig
		}

		listener := NewListener(ListenerConfig{
			Address:        lc.Address,
			Mode:           lc.Mode,
			TLSConfig:      tlsCfg,
			IdleTimeout:    s.cfg.Timeouts.ConnectionTimeout(),
			CommandTimeout: s.cfg.Timeouts.CommandTimeout(),
			LogTransaction: s.cfg.LogLevel == "debug",
			Logger:         s.logger,
			Handler:        s.handler,
		})
		s.listeners = append(s.listeners, listener)
	}

	s.mu.Unlock()

	s.logger.Info("starting server",
		slog.String("hostname", s.cfg.Hostname),
		slog.Int("listener_count", len(s.listeners)),
	)

	// Start all listeners in goroutines
	var wg sync.WaitGroup
	errChan := make(chan error, len(s.listeners))

	for _, l := range s.listeners {
		wg.Add(1)
		go func(listener *Listener) {
			defer wg.Done()
			if err := listener.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("listener %s: %w", listener.Address(), err)
			}
		}(l)
	}

	// Wait for context cancellation
	<-ctx.Done()

	s.logger.Info("server shutting down")

	// Wait for all listeners to stop
	wg.Wait()

	// Check for any errors
	close(errChan)
	var firstErr error
	for err := range errChan {
		if firstErr == nil {
			firstErr = err
		}
		s.logger.Error("listener error", slog.String("error", err.Error()))
	}

	s.logger.Info("server stopped")

	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// Shutdown gracefully stops the server.
// It closes all listeners and waits for connections to complete.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.listeners {
		_ = l.Close()
	}
}

// Logger returns the server's logger.
func (s *Server) Logger() *slog.Logger {
	return s.logger
}

// TLSConfig returns the server's TLS configuration, if any.
func (s *Server) TLSConfig() *tls.Config {
	return s.tlsConfig
}

// Config returns the server's configuration.
func (s *Server) Config() *config.Config {
	return s.cfg
}

// defaultHandler is a placeholder handler that logs connections.
// This should be replaced with actual POP3 protocol handling.
func (s *Server) defaultHandler(ctx context.Context, conn *Connection) {
	logger := logging.FromContext(ctx)
	logger.Info("connection handler not implemented - closing connection")
}
