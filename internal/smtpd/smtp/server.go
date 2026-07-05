package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/logging"
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
	Backend        *Backend
	Listeners      []config.ListenerConfig
	Hostname       string
	TLSConfig      *tls.Config
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxMessageSize int
	MaxRecipients  int
	Logger         *slog.Logger
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
		// Route go-smtp's error sink (SMTP-session panic recovery plus
		// connection/accept errors) through slog at error level. Left as its
		// default it logs to stderr via log.Default(), bypassing structured
		// logging. See issue #135.
		s.ErrorLog = logging.NewStdLogger(logger.With("component", "smtpd"))
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
			// AllowInsecureAuth must be true for SMTPS because go-smtp
			// cannot detect TLS on connections wrapped by oneConnListener's
			// notifyConn (the *tls.Conn type assertion fails). Since SMTPS
			// connections are always TLS by definition, this is safe.
			// Our AuthMechanisms() has its own TLS check as a second layer.
			s.AllowInsecureAuth = true

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

	// Own the listeners (rather than entry.server.ListenAndServe, which creates
	// them internally) so shutdown can stop accepting BEFORE draining. go-smtp's
	// Serve calls s.wg.Add per accepted connection while Shutdown calls s.wg.Wait
	// in a goroutine; if a connection is accepted as Shutdown begins, those race
	// on the WaitGroup counter (a go-smtp v0.24.0 bug). Closing the listener and
	// waiting for Serve to return first guarantees no concurrent wg.Add.
	listeners := make([]net.Listener, len(s.entries))
	for i, entry := range s.entries {
		var ln net.Listener
		var err error
		if entry.mode == config.ModeSmtps {
			ln, err = tls.Listen("tcp", entry.server.Addr, entry.server.TLSConfig)
		} else {
			ln, err = net.Listen("tcp", entry.server.Addr)
		}
		if err != nil {
			for _, l := range listeners {
				if l != nil {
					_ = l.Close()
				}
			}
			return fmt.Errorf("listen %s: %w", entry.server.Addr, err)
		}
		listeners[i] = ln
	}

	// shuttingDown gates suppression of the expected "use of closed network
	// connection" error that Serve returns once we close the listeners.
	shuttingDown := make(chan struct{})

	for i, entry := range s.entries {
		s.wg.Add(1)
		go func(entry serverEntry, ln net.Listener) {
			defer s.wg.Done()
			s.logger.Info("starting listener",
				slog.String("address", entry.server.Addr),
				slog.String("mode", string(entry.mode)))
			if err := entry.server.Serve(ln); err != nil {
				select {
				case <-shuttingDown:
					// Expected: we closed the listener to begin shutdown.
				default:
					errChan <- fmt.Errorf("server %s: %w", entry.server.Addr, err)
				}
			}
		}(entry, listeners[i])
	}

	// Wait for context cancellation
	<-ctx.Done()
	s.logger.Info("shutting down servers")
	close(shuttingDown)

	// Stop accepting, then wait for every Serve loop to return. After this no
	// go-smtp wg.Add can run, so the subsequent Shutdown (wg.Wait) is race-free.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	s.wg.Wait()

	// Gracefully drain in-flight connections.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, entry := range s.entries {
		// Shutdown re-closes the (already closed) listener, so a net.ErrClosed
		// here is expected, not a failure.
		if err := entry.server.Shutdown(shutdownCtx); err != nil &&
			!errors.Is(err, net.ErrClosed) && !errors.Is(err, gosmtp.ErrServerClosed) {
			s.logger.Error("error shutting down server",
				slog.String("address", entry.server.Addr),
				slog.String("error", err.Error()))
		}
	}

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
