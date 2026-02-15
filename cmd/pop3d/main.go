package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	_ "github.com/infodancer/maildancer/auth/passwd" // Register passwd backend
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir backend
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/infodancer/maildancer/internal/pop3d/server"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
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

	// Create logger
	logger := logging.NewLogger(cfg.LogLevel)

	// Load TLS configuration if certificates are specified
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
		logger.Info("TLS configured",
			slog.String("cert", cfg.TLS.CertFile),
			slog.String("min_version", cfg.TLS.MinVersion))
	}

	// Set up metrics collector
	var collector metrics.Collector = &metrics.NoopCollector{}
	if cfg.Metrics.Enabled {
		collector = metrics.NewPrometheusCollector(prometheus.DefaultRegisterer)
	}

	// Create authentication agent if configured
	var authAgent auth.AuthenticationAgent
	if cfg.Auth.IsConfigured() {
		agentConfig := auth.AuthAgentConfig{
			Type:              cfg.Auth.Type,
			CredentialBackend: cfg.Auth.CredentialBackend,
			KeyBackend:        cfg.Auth.KeyBackend,
			Options:           cfg.Auth.Options,
		}
		authAgent, err = auth.OpenAuthAgent(agentConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating auth agent: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if err := authAgent.Close(); err != nil {
				logger.Error("error closing auth agent", "error", err)
			}
		}()
		logger.Info("authentication enabled", "type", cfg.Auth.Type)
	}

	// Create message store if configured
	var msgStore msgstore.MessageStore
	if cfg.Maildir != "" {
		store, err := msgstore.Open(msgstore.StoreConfig{
			Type:     "maildir",
			BasePath: cfg.Maildir,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening message store: %v\n", err)
			os.Exit(1)
		}
		msgStore = store
		logger.Info("message store enabled", "type", "maildir", "path", cfg.Maildir)
	}

	// Create domain provider if configured
	var domainProvider *domain.FilesystemDomainProvider
	if cfg.DomainsPath != "" {
		domainProvider = domain.NewFilesystemDomainProvider(cfg.DomainsPath, logger)
		defer func() {
			if err := domainProvider.Close(); err != nil {
				logger.Error("error closing domain provider", "error", err)
			}
		}()
		logger.Info("domain provider enabled", "path", cfg.DomainsPath)
	}

	// Create server
	srv, err := server.New(server.Config{
		Cfg:       &cfg,
		TLSConfig: tlsConfig,
		Logger:    logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
	}

	// Set POP3 protocol handler
	handler := pop3.Handler(cfg.Hostname, authAgent, msgStore, domainProvider, tlsConfig, collector)
	srv.SetHandler(handler)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Start metrics server if enabled
	if cfg.Metrics.Enabled {
		metricsServer := metrics.NewPrometheusServer(cfg.Metrics.Address, cfg.Metrics.Path)
		go func() {
			if err := metricsServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("metrics server error", "error", err)
			}
		}()
		logger.Info("metrics server started", "address", cfg.Metrics.Address, "path", cfg.Metrics.Path)
	}

	logger.Info("starting pop3d", "hostname", cfg.Hostname, "listeners", len(cfg.Listeners))

	// Run server
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	logger.Info("POP3 server stopped")
}
