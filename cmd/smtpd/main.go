package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir storage backend
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/server"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"
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

	// Create and set the SMTP handler
	handler := smtp.Handler(cfg.Hostname, collector, delivery)
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
