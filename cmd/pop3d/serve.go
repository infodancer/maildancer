package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/prometheus/client_golang/prometheus"
)

// runServe is the listener process: it accepts client connections and hands
// each one to a protocol-handler subprocess (mail-security-model.md, #179).
// It never speaks POP3 and never loads TLS keys; handlers do both.
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

	// Handlers re-read the config themselves; hand them a path that
	// survives any working-directory difference.
	configPath, err := filepath.Abs(flags.ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving config path: %v\n", err)
		os.Exit(1)
	}

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving executable path: %v\n", err)
		os.Exit(1)
	}

	// Connection counters live here in the dispatcher (spawn/reap);
	// session-level metrics are the handlers' business.
	var collector metrics.Collector = &metrics.NoopCollector{}
	if cfg.Metrics.Enabled {
		collector = metrics.NewPrometheusCollector(prometheus.DefaultRegisterer)
	}

	dispatcher, err := pop3.NewDispatcher(pop3.DispatcherConfig{
		Config:     cfg,
		ExecPath:   execPath,
		ConfigPath: configPath,
		Collector:  collector,
		Logger:     logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building dispatcher: %v\n", err)
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

	if cfg.Metrics.Enabled {
		metricsServer := metrics.NewPrometheusServer(cfg.Metrics.Address, cfg.Metrics.Path)
		go func() {
			if err := metricsServer.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("metrics server error", "error", err)
			}
		}()
		logger.Info("metrics server started", "address", cfg.Metrics.Address, "path", cfg.Metrics.Path)
	}

	logger.Info("starting pop3d dispatcher", "hostname", cfg.Hostname, "listeners", len(cfg.Listeners))

	if err := dispatcher.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("dispatcher error", "error", err)
	}
	logger.Info("POP3 server stopped")
}
