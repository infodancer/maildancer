package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"
)

// connFD is the file descriptor number used to pass the TCP socket from the
// listener parent to the protocol-handler subprocess. It is the first entry in
// cmd.ExtraFiles, which the OS maps to fd 3 (stdin=0, stdout=1, stderr=2).
const connFD = 3

// metricsFD is the file descriptor for the metrics-report pipe to the parent,
// the second cmd.ExtraFiles entry (fd 4). Present only when metrics are enabled;
// the handler records into a private collector and writes the accumulated
// families here just before exiting so the parent can aggregate them.
const metricsFD = 4

func runProtocolHandler() {
	flags := config.ParseFlags()

	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.LogLevel)

	// Connection metadata supplied by the parent listener process.
	clientIP := os.Getenv("SMTPD_CLIENT_IP")
	listenerMode := config.ListenerMode(os.Getenv("SMTPD_LISTENER_MODE"))
	if listenerMode == "" {
		listenerMode = config.ModeSmtp
	}

	logger.Debug("protocol-handler started",
		slog.String("client_ip", clientIP),
		slog.String("mode", string(listenerMode)))

	// Load TLS configuration (needed for STARTTLS on SMTP/Submission and
	// for implicit TLS on SMTPS).
	var tlsConfig *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "protocol-handler: error loading TLS certificate: %v\n", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   cfg.TLS.MinTLSVersion(),
		}
	}

	// Spam checker runs in the handler subprocess so it has access to the
	// message data during the DATA command.
	spamChecker, spamCheckConfig := createSpamChecker(cfg, logger)
	if spamChecker != nil {
		defer func() {
			if err := spamChecker.Close(); err != nil {
				logger.Error("error closing spam checker", "error", err)
			}
		}()
	}

	// Metrics collector. When enabled, record into a private registry and flush
	// the accumulated families to the parent over fd 4 at exit; the parent owns
	// the /metrics endpoint and aggregates across all handler subprocesses.
	var collector metrics.Collector = &metrics.NoopCollector{}
	var flushMetrics func()
	if cfg.Metrics.Enabled {
		c, reg := metrics.NewHandlerCollector()
		collector = c
		if reportFile := os.NewFile(uintptr(metricsFD), "smtp-metrics"); reportFile != nil {
			flushMetrics = func() {
				if err := metrics.WriteReport(reportFile, reg); err != nil {
					logger.Debug("failed to write metrics report", slog.String("error", err.Error()))
				}
				_ = reportFile.Close()
			}
		}
	}

	// Build the full auth/delivery stack. Each subprocess gets its own stack
	// instance; there is no shared state with the parent listener process.
	stack, err := smtp.NewStack(smtp.StackConfig{
		Config:      cfg,
		TLSConfig:   tlsConfig,
		SpamChecker: spamChecker,
		SpamConfig:  spamCheckConfig,
		Collector:   collector,
		Logger:      logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error creating stack: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := stack.Close(); err != nil {
			logger.Error("error closing stack", "error", err)
		}
	}()

	// Reconstruct the TCP connection from the fd passed by the parent.
	// ExtraFiles[0] maps to fd 3 in the child process.
	connFile := os.NewFile(uintptr(connFD), "smtp-conn")
	if connFile == nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: fd %d not available\n", connFD)
		os.Exit(1)
	}
	netConn, err := net.FileConn(connFile)
	_ = connFile.Close() // done with the os.File wrapper; netConn holds its own dup
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error reconstructing connection: %v\n", err)
		os.Exit(1)
	}

	// Run exactly one SMTP session then exit.
	if err := stack.Server.RunSingleConn(netConn, listenerMode, tlsConfig); err != nil {
		logger.Debug("session ended", slog.String("error", err.Error()))
	}

	// Ship the session's metrics to the parent. Done after the session returns
	// so every counter (including the connection-close path) is recorded.
	if flushMetrics != nil {
		flushMetrics()
	}
}
