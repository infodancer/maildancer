package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildir"
	"github.com/infodancer/maildancer/msgstore"
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
	if cfg.Delivery.Maildir != "" {
		delivery = maildir.NewDelivery(cfg.Delivery.Maildir)
		srv.Logger().Info("maildir delivery enabled", "path", cfg.Delivery.Maildir)
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
