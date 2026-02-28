package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
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

	logger.Info("starting pop3d",
		"hostname", cfg.Hostname,
		"listeners", len(cfg.Listeners),
		"exec", execPath)

	srv := pop3.NewSubprocessServer(cfg.Listeners, execPath, configPath, cfg.DomainsPath, cfg.MailSessionPath, logger)
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	logger.Info("POP3 server stopped")
}
