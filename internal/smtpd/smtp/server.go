package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// serverEntry holds a go-smtp server and its mode.
type serverEntry struct {
	server *gosmtp.Server
	mode   config.ListenerMode
}

// Server wraps multiple go-smtp servers for multi-mode listener support.
type Server struct {
	entries []serverEntry
	logger  *slog.Logger
	wg      sync.WaitGroup
}

// ServerConfig holds configuration for creating a multi-mode Server.
type ServerConfig struct {
	Backend      *Backend
	Listeners    []config.ListenerConfig
	Hostname     string
	TLSConfig    *tls.Config
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxMessageSize int
	MaxRecipients  int
	Logger       *slog.Logger
}

// NewServer creates a new multi-mode Server with go-smtp servers for each listener.
func NewServer(cfg ServerConfig) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	srv := &Server{
		entries: make([]serverEntry, 0, len(cfg.Listeners)),
		logger:  logger,
	}

	for _, listener := range cfg.Listeners {
		s := gosmtp.NewServer(cfg.Backend)
		s.Addr = listener.Address
		s.Domain = cfg.Hostname
		s.ReadTimeout = cfg.ReadTimeout
		s.WriteTimeout = cfg.WriteTimeout
		s.MaxMessageBytes = int64(cfg.MaxMessageSize)
		s.MaxRecipients = cfg.MaxRecipients
		s.EnableSMTPUTF8 = true

		switch listener.Mode {
		case config.ModeSmtp:
			// Standard SMTP on port 25
			// AUTH only allowed after STARTTLS (except localhost)
			s.AllowInsecureAuth = false
			if cfg.TLSConfig != nil {
				s.TLSConfig = cfg.TLSConfig
			}

		case config.ModeSubmission:
			// Submission on port 587
			// Requires STARTTLS before AUTH
			s.AllowInsecureAuth = false
			if cfg.TLSConfig != nil {
				s.TLSConfig = cfg.TLSConfig
			}

		case config.ModeSmtps:
			// SMTPS on port 465 (implicit TLS)
			if cfg.TLSConfig == nil {
				return nil, fmt.Errorf("listener %s: TLS required for SMTPS mode but not configured", listener.Address)
			}
			s.TLSConfig = cfg.TLSConfig
			// AUTH is allowed since connection is already TLS
			s.AllowInsecureAuth = false

		case config.ModeAlt:
			// Alternative mode - similar to SMTP
			s.AllowInsecureAuth = false
			if cfg.TLSConfig != nil {
				s.TLSConfig = cfg.TLSConfig
			}
		}

		srv.entries = append(srv.entries, serverEntry{server: s, mode: listener.Mode})
		logger.Info("configured listener",
			slog.String("address", listener.Address),
			slog.String("mode", string(listener.Mode)))
	}

	return srv, nil
}

// Run starts all servers and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errChan := make(chan error, len(s.entries))

	// Start all servers
	for _, entry := range s.entries {
		s.wg.Add(1)
		go func(entry serverEntry) {
			defer s.wg.Done()

			var err error
			if entry.mode == config.ModeSmtps {
				s.logger.Info("starting SMTPS listener", slog.String("address", entry.server.Addr))
				err = entry.server.ListenAndServeTLS()
			} else {
				s.logger.Info("starting listener", slog.String("address", entry.server.Addr))
				err = entry.server.ListenAndServe()
			}

			if err != nil {
				errChan <- fmt.Errorf("server %s: %w", entry.server.Addr, err)
			}
		}(entry)
	}

	// Wait for context cancellation
	<-ctx.Done()

	s.logger.Info("shutting down servers")

	// Gracefully close all servers
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, entry := range s.entries {
		if err := entry.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("error shutting down server",
				slog.String("address", entry.server.Addr),
				slog.String("error", err.Error()))
		}
	}

	s.wg.Wait()
	s.logger.Info("all servers stopped")

	// Check for any startup errors
	close(errChan)
	var firstErr error
	for err := range errChan {
		if firstErr == nil {
			firstErr = err
		}
		s.logger.Error("server error", slog.String("error", err.Error()))
	}

	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// RunSingleConn serves exactly one SMTP connection using the server entry matching
// the given listener mode. Blocks until the session ends.
// Used by protocol-handler subprocesses to handle one connection and exit.
func (s *Server) RunSingleConn(conn net.Conn, mode config.ListenerMode, tlsConfig *tls.Config) error {
	// Find the entry whose mode matches, falling back to the first entry.
	var entry *serverEntry
	for i := range s.entries {
		if s.entries[i].mode == mode {
			entry = &s.entries[i]
			break
		}
	}
	if entry == nil && len(s.entries) > 0 {
		entry = &s.entries[0]
	}
	if entry == nil {
		return fmt.Errorf("no server entries configured")
	}

	// SMTPS uses implicit TLS: wrap conn before handing to go-smtp.
	// For SMTP/Submission modes, go-smtp handles STARTTLS via entry.server.TLSConfig.
	if mode == config.ModeSmtps {
		if tlsConfig == nil {
			return fmt.Errorf("SMTPS mode requires TLS configuration")
		}
		conn = tls.Server(conn, tlsConfig)
	}

	ln := newOneConnListener(conn)
	return entry.server.Serve(ln)
}
