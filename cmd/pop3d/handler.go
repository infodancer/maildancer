package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
)

// runProtocolHandler is the child half of the fork-per-connection model
// (mail-security-model.md, #179): it inherits one accepted client connection
// as fd 3 from the dispatcher, re-reads the configuration named by --config
// (plus any -tls-cert/-tls-key overrides the dispatcher forwarded), and
// serves exactly one POP3 session before exiting.
func runProtocolHandler() {
	flags := config.ParseFlags()

	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.LogLevel)

	mode := config.ListenerMode(os.Getenv(pop3.EnvListenerMode))
	if mode == "" {
		mode = config.ModePop3
	}
	if mode != config.ModePop3 && mode != config.ModePop3s {
		logger.Error("unknown listener mode", slog.String("mode", string(mode)))
		os.Exit(1)
	}
	clientIP := os.Getenv(pop3.EnvClientIP)

	var tlsConfig *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			logger.Error("error loading TLS certificate", slog.String("error", err.Error()))
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   cfg.TLS.MinTLSVersion(),
		}
	}

	// Interim state (#179): no per-handler metrics reporting yet, so
	// session-level series are dropped in the handler. The dispatcher
	// maintains the connection counters; the fd-4 report pipe is a
	// follow-up (#188).
	stack, err := pop3.NewStack(pop3.StackConfig{
		Config:    cfg,
		TLSConfig: tlsConfig,
		Collector: &metrics.NoopCollector{},
		Logger:    logger,
	})
	if err != nil {
		logger.Error("error building stack", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer stack.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here

	conn, err := connfork.ChildConn()
	if err != nil {
		logger.Error("no inherited connection", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Debug("serving connection",
		slog.String("client_ip", clientIP),
		slog.String("mode", string(mode)))

	if err := stack.RunSingleConn(conn, mode); err != nil {
		// Session-level failures are the client's business, not the
		// operator's; the session itself already logged specifics.
		logger.Debug("session ended with error", slog.String("error", err.Error()))
	}
}
