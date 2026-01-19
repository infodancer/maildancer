// Package logging provides centralized logging for the POP3 server.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// contextKey is used for storing loggers in context.
type contextKey struct{}

var loggerKey = contextKey{}

// connectionCounter is used to generate unique connection IDs.
var connectionCounter atomic.Uint64

// NewLogger creates a new slog.Logger with the specified level.
func NewLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
	}
	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}

// WithConnection returns a new logger with connection-specific attributes.
// It generates a unique connection ID for log correlation.
func WithConnection(logger *slog.Logger, remoteAddr string) *slog.Logger {
	connID := connectionCounter.Add(1)
	return logger.With(
		slog.Uint64("conn_id", connID),
		slog.String("remote_addr", remoteAddr),
	)
}

// WithListener returns a new logger with listener-specific attributes.
func WithListener(logger *slog.Logger, address string, mode string) *slog.Logger {
	return logger.With(
		slog.String("listener", address),
		slog.String("mode", mode),
	)
}

// FromContext retrieves the logger from the context.
// Returns the default logger if none is found.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// NewContext returns a new context with the logger attached.
func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// TransactionWriter wraps an io.Writer to log all data written.
// Used for debugging full POP3 transactions.
type TransactionWriter struct {
	w      io.Writer
	logger *slog.Logger
	prefix string
}

// NewTransactionWriter creates a writer that logs all data.
func NewTransactionWriter(w io.Writer, logger *slog.Logger, prefix string) *TransactionWriter {
	return &TransactionWriter{
		w:      w,
		logger: logger,
		prefix: prefix,
	}
}

// Write writes data and logs it.
func (tw *TransactionWriter) Write(p []byte) (n int, err error) {
	n, err = tw.w.Write(p)
	if n > 0 {
		tw.logger.Debug("transaction",
			slog.String("direction", tw.prefix),
			slog.String("data", string(p[:n])),
		)
	}
	return n, err
}

// TransactionReader wraps an io.Reader to log all data read.
type TransactionReader struct {
	r      io.Reader
	logger *slog.Logger
	prefix string
}

// NewTransactionReader creates a reader that logs all data.
func NewTransactionReader(r io.Reader, logger *slog.Logger, prefix string) *TransactionReader {
	return &TransactionReader{
		r:      r,
		logger: logger,
		prefix: prefix,
	}
}

// Read reads data and logs it.
func (tr *TransactionReader) Read(p []byte) (n int, err error) {
	n, err = tr.r.Read(p)
	if n > 0 {
		tr.logger.Debug("transaction",
			slog.String("direction", tr.prefix),
			slog.String("data", string(p[:n])),
		)
	}
	return n, err
}
