package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/infodancer/maildancer/auth"
	_ "github.com/infodancer/maildancer/auth/passwd" // Register passwd auth backend
	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/server"
)

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config flag is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.WebAdmin.LogLevel)

	// Open admin auth agent
	authAgent, err := auth.OpenAuthAgent(auth.AuthAgentConfig{
		Type:              "passwd",
		CredentialBackend: cfg.WebAdmin.Auth.PasswdFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening admin auth: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := authAgent.Close(); err != nil {
			logger.Error("error closing auth agent", "error", err)
		}
	}()

	srv, err := server.New(cfg.WebAdmin, server.Deps{
		AuthAgent: authAgent,
	}, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
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

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// newLogger creates a structured logger at the specified level.
func newLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})
	return slog.New(handler)
}
