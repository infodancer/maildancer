package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
)

func runServe() {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Load TLS configuration if specified.
	var tlsConfig *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading TLS certificate: %v\n", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   cfg.TLS.MinTLSVersion(),
		}
	}

	// Metrics HTTP server.
	if cfg.Metrics.Enabled {
		metricsServer := metrics.NewPrometheusServer(cfg.Metrics.Address, cfg.Metrics.Path)
		go func() {
			if err := metricsServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	logger.Info("starting pop3d",
		"hostname", cfg.Hostname,
		"listeners", len(cfg.Listeners))

	stack, err := pop3.NewStack(pop3.StackConfig{
		Config:    cfg,
		TLSConfig: tlsConfig,
		Logger:    logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating stack: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := stack.Close(); err != nil {
			logger.Error("error closing stack", "error", err)
		}
	}()

	if err := stack.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	logger.Info("POP3 server stopped")
}
