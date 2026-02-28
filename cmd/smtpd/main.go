package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/infodancer/maildancer/auth"
	_ "github.com/infodancer/maildancer/auth/passwd" // Register passwd auth backend
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir storage backend
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/rspamd"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
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

	// Create delivery agent if configured
	var delivery msgstore.DeliveryAgent
	if cfg.Delivery.Type != "" {
		storeConfig := msgstore.StoreConfig{
			Type:     cfg.Delivery.Type,
			BasePath: cfg.Delivery.BasePath,
			Options:  cfg.Delivery.Options,
		}
		store, err := msgstore.Open(storeConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating delivery agent: %v\n", err)
			os.Exit(1)
		}
		delivery = store
		logger.Info("delivery enabled", "type", cfg.Delivery.Type, "path", cfg.Delivery.BasePath)
	}

	// Create authentication agent if configured
	var authAgent auth.AuthenticationAgent
	if cfg.Auth.IsEnabled() {
		agentConfig := auth.AuthAgentConfig{
			Type:              cfg.Auth.AgentType,
			CredentialBackend: cfg.Auth.CredentialBackend,
			KeyBackend:        cfg.Auth.KeyBackend,
			Options:           cfg.Auth.Options,
		}
		authAgent, err = auth.OpenAuthAgent(agentConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating authentication agent: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if err := authAgent.Close(); err != nil {
				logger.Error("error closing auth agent", "error", err)
			}
		}()
		logger.Info("authentication enabled", "type", cfg.Auth.AgentType)
	}

	// Create spam checker from config
	spamChecker, spamCheckConfig := createSpamChecker(cfg, logger)
	if spamChecker != nil {
		defer func() {
			if err := spamChecker.Close(); err != nil {
				logger.Error("error closing spam checker", "error", err)
			}
		}()
	}

	// Create domain provider if configured
	var domainProvider domain.DomainProvider
	if cfg.DomainsPath != "" {
		dp := domain.NewFilesystemDomainProvider(cfg.DomainsPath, logger)
		if cfg.DomainsDataPath != "" {
			dp = dp.WithDataPath(cfg.DomainsDataPath)
		}
		domainProvider = dp.WithDefaults(domain.DomainConfig{
				Auth: domain.DomainAuthConfig{
					Type:              "passwd",
					CredentialBackend: "passwd",
					KeyBackend:        "keys",
				},
				MsgStore: domain.DomainMsgStoreConfig{
					Type:     "maildir",
					BasePath: "users",
				},
			})
		defer func() {
			if err := domainProvider.Close(); err != nil {
				logger.Error("error closing domain provider", "error", err)
			}
		}()
		logger.Info("domain provider enabled", "path", cfg.DomainsPath)
	}

	// Create auth router (centralizes domain-aware auth routing)
	authRouter := domain.NewAuthRouter(domainProvider, authAgent)

	// Create the go-smtp backend
	// Build temp dir path: on the same filesystem as the mail store so
	// temp files can be renamed atomically into the maildir.
	var tempDir string
	if cfg.Delivery.BasePath != "" {
		tempDir = filepath.Join(cfg.Delivery.BasePath, "tmp")
	}

	backend := smtp.NewBackend(smtp.BackendConfig{
		Hostname:       cfg.Hostname,
		Delivery:       delivery,
		AuthAgent:      authAgent,
		AuthRouter:     authRouter,
		DomainProvider: domainProvider,
		SpamChecker:    spamChecker,
		SpamConfig:     spamCheckConfig,
		Collector:      collector,
		MaxRecipients:  cfg.Limits.MaxRecipients,
		MaxMessageSize: int64(cfg.Limits.MaxMessageSize),
		TempDir:        tempDir,
		Logger:         logger,
	})

	// Create the multi-mode server
	srv, err := smtp.NewServer(smtp.ServerConfig{
		Backend:        backend,
		Listeners:      cfg.Listeners,
		Hostname:       cfg.Hostname,
		TLSConfig:      tlsConfig,
		ReadTimeout:    cfg.Timeouts.ConnectionTimeout(),
		WriteTimeout:   cfg.Timeouts.ConnectionTimeout(),
		MaxMessageSize: cfg.Limits.MaxMessageSize,
		MaxRecipients:  cfg.Limits.MaxRecipients,
		Logger:         logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
	}

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
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
	}

	logger.Info("starting smtpd", "hostname", cfg.Hostname, "listeners", len(cfg.Listeners))

	// Run the server
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// createSpamChecker creates a spam checker from the configuration.
func createSpamChecker(cfg config.Config, logger *slog.Logger) (spamcheck.Checker, config.SpamCheckConfig) {
	if !cfg.SpamCheck.IsEnabled() {
		return nil, config.SpamCheckConfig{}
	}

	checkers, names := createCheckersFromConfig(cfg.SpamCheck, logger)
	if len(checkers) == 0 {
		return nil, config.SpamCheckConfig{}
	}

	logger.Info("spam checking enabled",
		"checkers", names,
		"mode", cfg.SpamCheck.Mode,
		"fail_mode", cfg.SpamCheck.GetFailMode(),
		"reject_threshold", cfg.SpamCheck.RejectThreshold)

	if len(checkers) == 1 {
		return checkers[0], cfg.SpamCheck
	}

	// Use multi-checker for multiple checkers
	multiConfig := spamcheck.MultiConfig{
		Mode:              cfg.SpamCheck.Mode,
		FailMode:          spamcheck.FailMode(cfg.SpamCheck.FailMode),
		RejectThreshold:   cfg.SpamCheck.RejectThreshold,
		TempFailThreshold: cfg.SpamCheck.TempFailThreshold,
		AddHeaders:        cfg.SpamCheck.AddHeaders,
	}
	return spamcheck.NewMultiChecker(checkers, multiConfig), cfg.SpamCheck
}

// createCheckersFromConfig creates spam checkers from the spamcheck config.
func createCheckersFromConfig(cfg config.SpamCheckConfig, logger *slog.Logger) ([]spamcheck.Checker, []string) {
	var checkers []spamcheck.Checker
	var names []string

	for _, checkerCfg := range cfg.Checkers {
		if !checkerCfg.IsEnabled() {
			continue
		}

		switch checkerCfg.Type {
		case "rspamd":
			checker := rspamd.NewChecker(checkerCfg.URL, checkerCfg.Password, checkerCfg.GetTimeout())
			checkers = append(checkers, checker)
			names = append(names, "rspamd")
			logger.Debug("created rspamd checker", "url", checkerCfg.URL)

		// Add more checker types here as they're implemented:
		// case "spamassassin":
		//     checker := spamassassin.NewChecker(checkerCfg.URL, checkerCfg.GetTimeout())
		//     checkers = append(checkers, checker)
		//     names = append(names, "spamassassin")

		default:
			logger.Warn("unknown spam checker type", "type", checkerCfg.Type)
		}
	}

	return checkers, names
}
