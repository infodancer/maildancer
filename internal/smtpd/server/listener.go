package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
)

// ConnectionHandler is called for each new connection.
// It receives the context and connection, and should handle the SMTP session.
type ConnectionHandler func(ctx context.Context, conn *Connection)

// Listener manages a single TCP listener for accepting SMTP connections.
type Listener struct {
	address   string
	mode      config.ListenerMode
	tlsConfig *tls.Config
	connCfg   ConnectionConfig
	handler   ConnectionHandler
	logger    *slog.Logger

	listener net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
}

// ListenerConfig holds configuration for creating a new Listener.
type ListenerConfig struct {
	Address        string
	Mode           config.ListenerMode
	TLSConfig      *tls.Config
	IdleTimeout    time.Duration
	CommandTimeout time.Duration
	LogTransaction bool
	Logger         *slog.Logger
	Handler        ConnectionHandler
}

// NewListener creates a new Listener with the given configuration.
func NewListener(cfg ListenerConfig) *Listener {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Listener{
		address:   cfg.Address,
		mode:      cfg.Mode,
		tlsConfig: cfg.TLSConfig,
		connCfg: ConnectionConfig{
			IdleTimeout:    cfg.IdleTimeout,
			CommandTimeout: cfg.CommandTimeout,
			LogTransaction: cfg.LogTransaction,
			Logger:         logger,
		},
		handler: cfg.Handler,
		logger:  logging.WithListener(logger, cfg.Address, string(cfg.Mode)),
	}
}

// Start begins listening for connections.
// It blocks until the context is cancelled or an unrecoverable error occurs.
func (l *Listener) Start(ctx context.Context) error {
	var err error
	var ln net.Listener

	// For SMTPS mode, wrap with TLS immediately
	if l.mode == config.ModeSmtps {
		if l.tlsConfig == nil {
			return errors.New("TLS configuration required for SMTPS mode")
		}
		ln, err = tls.Listen("tcp", l.address, l.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", l.address)
	}

	if err != nil {
		return err
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()

	l.logger.Info("listener started",
		slog.String("address", l.address),
		slog.String("mode", string(l.mode)),
	)

	// Start accept loop in goroutine
	go l.acceptLoop(ctx)

	// Wait for context cancellation
	<-ctx.Done()

	l.logger.Info("listener shutting down")

	// Close the listener to stop accepting new connections
	if err := l.Close(); err != nil {
		l.logger.Debug("error closing listener",
			slog.String("error", err.Error()),
		)
	}

	// Wait for all connections to complete
	l.wg.Wait()

	l.logger.Info("listener stopped")
	return ctx.Err()
}

// acceptLoop accepts connections until the listener is closed.
func (l *Listener) acceptLoop(ctx context.Context) {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()

			if closed {
				return
			}

			// Check if it's a temporary error
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				l.logger.Warn("temporary accept error",
					slog.String("error", err.Error()),
				)
				time.Sleep(5 * time.Millisecond)
				continue
			}

			l.logger.Error("accept error",
				slog.String("error", err.Error()),
			)
			return
		}

		// Handle connection in its own goroutine
		l.wg.Add(1)
		go l.handleConnection(ctx, conn)
	}
}

// handleConnection wraps a connection and calls the handler.
func (l *Listener) handleConnection(ctx context.Context, netConn net.Conn) {
	defer l.wg.Done()

	// Create connection wrapper
	conn := NewConnection(netConn, l.connCfg)

	conn.Logger().Info("connection accepted")

	// Create connection-specific context
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Attach logger to context
	connCtx = logging.NewContext(connCtx, conn.Logger())

	// Set initial idle timeout
	if err := conn.ResetIdleTimeout(); err != nil {
		conn.Logger().Error("failed to set initial timeout",
			slog.String("error", err.Error()),
		)
		_ = conn.Close()
		return
	}

	// Start idle monitor
	go conn.IdleMonitor(connCtx)

	// Call the connection handler
	if l.handler != nil {
		l.handler(connCtx, conn)
	}

	_ = conn.Close()
	conn.Logger().Info("connection closed")
}

// Close stops the listener from accepting new connections.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

// Address returns the listener's address.
func (l *Listener) Address() string {
	return l.address
}

// Mode returns the listener's mode.
func (l *Listener) Mode() config.ListenerMode {
	return l.mode
}

// TLSConfig returns the TLS configuration, if any.
// For non-SMTPS modes, this can be used for STARTTLS.
func (l *Listener) TLSConfig() *tls.Config {
	return l.tlsConfig
}
