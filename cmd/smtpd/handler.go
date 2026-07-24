package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"
)

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
		reportFile := connfork.ChildReportPipe()
		flushMetrics = func() {
			if err := metrics.WriteReport(reportFile, reg); err != nil {
				logger.Debug("failed to write metrics report", slog.String("error", err.Error()))
			}
			_ = reportFile.Close()
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
	netConn, err := connfork.ChildConn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: %v\n", err)
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
