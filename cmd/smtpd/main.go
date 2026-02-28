package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/infodancer/maildancer/auth/passwd"    // Register passwd auth backend
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir storage backend
	"github.com/infodancer/maildancer/internal/smtpd/config"
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

	// Create spam checker from config (stays in main.go per project constraints)
	spamChecker, spamCheckConfig := createSpamChecker(cfg, logger)
	if spamChecker != nil {
		defer func() {
			if err := spamChecker.Close(); err != nil {
				logger.Error("error closing spam checker", "error", err)
			}
		}()
	}

	// Wire up all components via Stack
	stack, err := smtp.NewStack(smtp.StackConfig{
		Config:      cfg,
		TLSConfig:   tlsConfig,
		SpamChecker: spamChecker,
		SpamConfig:  spamCheckConfig,
		Collector:   collector,
		Logger:      logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server stack: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := stack.Close(); err != nil {
			logger.Error("error closing server stack", "error", err)
		}
	}()

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
	if err := stack.Run(ctx); err != nil && err != context.Canceled {
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
