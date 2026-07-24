package backend

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/imapd/notify"
	"github.com/infodancer/maildancer/internal/liblog"
)

// StackConfig groups the configuration needed to build a Stack.
// TLSConfig is caller-supplied; tests may omit it (nil = plain IMAP only).
type StackConfig struct {
	Config    config.Config
	TLSConfig *tls.Config
	Collector metrics.Collector // nil → NoopCollector
	Logger    *slog.Logger      // nil → slog.Default()
}

// Stack owns the components of one imapd protocol-handler process and
// manages their lifecycle. In the fork-per-connection model (#179) a Stack
// serves a single connection via ServeConn; the listening side is Dispatcher.
type Stack struct {
	srv       *imapserver.Server
	tlsConfig *tls.Config
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

	s := &Stack{logger: logger, tlsConfig: cfg.TLSConfig}

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
			s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
			return nil, err
		}
		s.closers = append(s.closers, subscriber)
		logger.Info("redis subscriber enabled", "url", cfg.Config.Redis.URL)
	}

	// Create session-manager client.
	smClient, err := NewSessionManagerClient(cfg.Config.SessionManager, logger)
	if err != nil {
		s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
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
		// "NO [SERVERBUG]") through slog. Left nil, go-imap falls back to
		// log.Default() and those faults bypass structured logging entirely
		// (#131). liblog.Level demotes benign client-caused messages (malformed
		// input, probe disconnects) to info so genuine faults stand out (#140).
		Logger: logging.NewStdLoggerFunc(logger.With("component", "imapd"), liblog.Level),
	}
	if cfg.Config.LogLevel == "debug" {
		opts.DebugWriter = logging.DebugWriter(logger, "imap-protocol")
	}
	srv := imapserver.New(opts)
	s.srv = srv
	// Registered last so Close shuts the IMAP server down before the
	// clients it depends on.
	s.closers = append(s.closers, srv)

	return s, nil
}

// ServeConn serves exactly one IMAP session on conn and returns when the
// session ends. It is the protocol-handler entry point in the
// fork-per-connection model (#179): the dispatcher accepts the connection,
// the handler subprocess serves it. ModeImaps wraps conn for implicit TLS
// using the stack's TLS config; ModeImap relies on go-imap's STARTTLS via
// Options.TLSConfig. go-imap only exposes Serve(net.Listener), so the single
// connection is fed through a one-shot listener; the net.ErrClosed that ends
// that listener after the session is filtered as success.
func (s *Stack) ServeConn(conn net.Conn, mode config.ListenerMode) error {
	if mode == config.ModeImaps {
		if s.tlsConfig == nil {
			_ = conn.Close()
			return errors.New("imaps connection requires a TLS configuration")
		}
		conn = tls.Server(conn, s.tlsConfig)
	}
	if err := s.srv.Serve(connfork.NewOneConnListener(conn)); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
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
