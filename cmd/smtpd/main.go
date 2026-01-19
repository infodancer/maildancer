package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildancer/auth"
	_ "github.com/infodancer/maildancer/auth/passwd" // Register passwd auth backend
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir storage backend
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/rspamd"
	"github.com/infodancer/maildancer/internal/smtpd/server"
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

	// Create the server
	srv, err := server.New(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
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
		srv.Logger().Info("delivery enabled", "type", cfg.Delivery.Type, "path", cfg.Delivery.BasePath)
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
				srv.Logger().Error("error closing auth agent", "error", err)
			}
		}()
		srv.Logger().Info("authentication enabled", "type", cfg.Auth.AgentType)
	}

	// Create spam checker from config
	spamChecker, spamCheckConfig := createSpamChecker(cfg, srv)
	if spamChecker != nil {
		defer func() {
			if err := spamChecker.Close(); err != nil {
				srv.Logger().Error("error closing spam checker", "error", err)
			}
		}()
	}

	// Create and set the SMTP handler
	handlerOpts := &smtp.HandlerOptions{
		SpamChecker:     spamChecker,
		SpamCheckConfig: spamCheckConfig,
	}
	handler := smtp.Handler(cfg.Hostname, collector, delivery, authAgent, srv.TLSConfig(), handlerOpts)
	srv.SetHandler(handler)

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		srv.Logger().Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Run the server
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// createSpamChecker creates a spam checker from the configuration.
func createSpamChecker(cfg config.Config, srv *server.Server) (spamcheck.Checker, config.SpamCheckConfig) {
	if !cfg.SpamCheck.IsEnabled() {
		return nil, config.SpamCheckConfig{}
	}

	checkers, names := createCheckersFromConfig(cfg.SpamCheck, srv)
	if len(checkers) == 0 {
		return nil, config.SpamCheckConfig{}
	}

	srv.Logger().Info("spam checking enabled",
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
func createCheckersFromConfig(cfg config.SpamCheckConfig, srv *server.Server) ([]spamcheck.Checker, []string) {
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
			srv.Logger().Debug("created rspamd checker", "url", checkerCfg.URL)

		// Add more checker types here as they're implemented:
		// case "spamassassin":
		//     checker := spamassassin.NewChecker(checkerCfg.URL, checkerCfg.GetTimeout())
		//     checkers = append(checkers, checker)
		//     names = append(names, "spamassassin")

		default:
			srv.Logger().Warn("unknown spam checker type", "type", checkerCfg.Type)
		}
	}

	return checkers, names
}
