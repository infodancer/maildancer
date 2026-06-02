package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/rspamd"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
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

	// Resolve config path to absolute so subprocesses find it regardless of cwd.
	configPath, err := filepath.Abs(flags.ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving config path: %v\n", err)
		os.Exit(1)
	}

	// Locate our own executable for subprocess spawning.
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error determining executable path: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Metrics HTTP server runs in the parent process. Per-connection metrics
	// are not aggregated from subprocesses in this release.
	if cfg.Metrics.Enabled {
		metricsServer := metrics.NewPrometheusServer(cfg.Metrics.Address, cfg.Metrics.Path)
		go func() {
			if err := metricsServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	logger.Info("starting smtpd",
		"hostname", cfg.Hostname,
		"listeners", len(cfg.Listeners),
		"exec", execPath)

	srv := smtp.NewSubprocessServer(cfg.Listeners, execPath, configPath, logger)
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// createSpamChecker builds a spam checker from the configuration.
// Called by both runServe (unused in parent) and runProtocolHandler.
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

	multiConfig := spamcheck.MultiConfig{
		Mode:              cfg.SpamCheck.Mode,
		FailMode:          spamcheck.FailMode(cfg.SpamCheck.FailMode),
		RejectThreshold:   cfg.SpamCheck.RejectThreshold,
		TempFailThreshold: cfg.SpamCheck.TempFailThreshold,
		AddHeaders:        cfg.SpamCheck.AddHeaders,
	}
	return spamcheck.NewMultiChecker(checkers, multiConfig), cfg.SpamCheck
}

// createCheckersFromConfig instantiates each configured spam checker.
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
		default:
			logger.Warn("unknown spam checker type", "type", checkerCfg.Type)
		}
	}

	return checkers, names
}
