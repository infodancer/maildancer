package server

import (
	"context"
	"crypto/tls"
	"log/slog"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// ConnectionHandler is called for each new connection.
// It receives the context and connection, and should handle the POP3 session.
type ConnectionHandler func(ctx context.Context, conn *Connection)

// Server holds the shared pieces of a POP3 session: configuration, TLS
// material, and the protocol handler. Accepting connections is not its job --
// the fork-per-connection dispatcher (pop3.Dispatcher over connfork) accepts
// and spawns a protocol-handler subprocess per connection, and each
// subprocess serves exactly one session via pop3.Stack.RunSingleConn
// (mail-security-model.md, #179).
type Server struct {
	cfg       *config.Config
	tlsConfig *tls.Config
	logger    *slog.Logger
	handler   ConnectionHandler
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

// SetHandler sets the connection handler for the server.
func (s *Server) SetHandler(handler ConnectionHandler) {
	s.handler = handler
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

// Handler returns the connection handler.
func (s *Server) Handler() ConnectionHandler {
	return s.handler
}
