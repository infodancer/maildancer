package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/infodancer/logging"
)

// Connection wraps a net.Conn with timeout management and optional transaction logging.
type Connection struct {
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	logger         *slog.Logger
	idleTimeout    time.Duration
	commandTimeout time.Duration
	logTx          bool

	mu           sync.Mutex
	lastActivity time.Time
	closed       bool
}

// ConnectionConfig holds configuration for a new connection.
type ConnectionConfig struct {
	IdleTimeout    time.Duration
	CommandTimeout time.Duration
	LogTransaction bool
	Logger         *slog.Logger
}

// NewConnection creates a new Connection wrapper.
func NewConnection(conn net.Conn, cfg ConnectionConfig) *Connection {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Create connection-scoped logger with remote address
	connLogger := logging.WithConnection(logger, conn.RemoteAddr().String())

	c := &Connection{
		conn:           conn,
		logger:         connLogger,
		idleTimeout:    cfg.IdleTimeout,
		commandTimeout: cfg.CommandTimeout,
		logTx:          cfg.LogTransaction,
		lastActivity:   time.Now(),
	}

	// Set up reader/writer with optional transaction logging
	var r io.Reader = conn
	var w io.Writer = conn

	if cfg.LogTransaction {
		r = logging.NewTransactionReader(conn, connLogger, "recv")
		w = logging.NewTransactionWriter(conn, connLogger, "send")
	}

	c.reader = bufio.NewReader(r)
	c.writer = bufio.NewWriter(w)

	return c
}

// Logger returns the connection-scoped logger.
func (c *Connection) Logger() *slog.Logger {
	return c.logger
}

// RemoteAddr returns the remote address of the connection.
func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// LocalAddr returns the local address of the connection.
func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Reader returns the buffered reader for the connection.
func (c *Connection) Reader() *bufio.Reader {
	return c.reader
}

// Writer returns the buffered writer for the connection.
func (c *Connection) Writer() *bufio.Writer {
	return c.writer
}

// Flush flushes the write buffer.
func (c *Connection) Flush() error {
	return c.writer.Flush()
}

// SetDeadline sets the read and write deadlines.
func (c *Connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ResetIdleTimeout resets the idle timeout deadline.
// Should be called after each successful read/write operation.
func (c *Connection) ResetIdleTimeout() error {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()

	if c.idleTimeout > 0 {
		return c.conn.SetDeadline(time.Now().Add(c.idleTimeout))
	}
	return nil
}

// SetCommandTimeout sets a deadline for the next command read.
func (c *Connection) SetCommandTimeout() error {
	if c.commandTimeout > 0 {
		return c.conn.SetReadDeadline(time.Now().Add(c.commandTimeout))
	}
	return nil
}

// Close closes the connection.
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("connection closed")
	return c.conn.Close()
}

// IsClosed returns true if the connection has been closed.
func (c *Connection) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Underlying returns the underlying net.Conn.
// Use with caution; prefer the Connection methods.
func (c *Connection) Underlying() net.Conn {
	return c.conn
}

// IsTLS returns true if the connection is encrypted with TLS.
func (c *Connection) IsTLS() bool {
	_, ok := c.conn.(*tls.Conn)
	return ok
}

// UpgradeToTLS upgrades the connection to TLS using the provided config.
// Returns an error if the upgrade fails or if already using TLS.
func (c *Connection) UpgradeToTLS(tlsConfig *tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.IsTLS() {
		return ErrAlreadyTLS
	}

	// Flush any pending writes before upgrade
	if err := c.writer.Flush(); err != nil {
		return err
	}

	// Perform TLS handshake
	tlsConn := tls.Server(c.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	// Replace the underlying connection
	c.conn = tlsConn

	// Recreate reader/writer with the new TLS connection
	var r io.Reader = tlsConn
	var w io.Writer = tlsConn

	if c.logTx {
		r = logging.NewTransactionReader(tlsConn, c.logger, "recv")
		w = logging.NewTransactionWriter(tlsConn, c.logger, "send")
	}

	c.reader = bufio.NewReader(r)
	c.writer = bufio.NewWriter(w)

	c.logger.Info("TLS upgrade completed")

	return nil
}

// IdleMonitor runs in a goroutine to monitor for idle connections.
// It will close the connection if idle timeout is exceeded.
// The monitor stops when the context is cancelled or the connection is closed.
func (c *Connection) IdleMonitor(ctx context.Context) {
	if c.idleTimeout <= 0 {
		return
	}

	ticker := time.NewTicker(c.idleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			idle := time.Since(c.lastActivity)
			c.mu.Unlock()

			if idle >= c.idleTimeout {
				c.logger.Info("closing idle connection",
					slog.Duration("idle_time", idle),
				)
				if err := c.Close(); err != nil {
					c.logger.Debug("error closing idle connection",
						slog.String("error", err.Error()),
					)
				}
				return
			}
		}
	}
}
