package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/grpcserver"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
)

func main() {
	configPath := flag.String("config", "", "path to TOML config file (required)")
	socketPath := flag.String("socket", "", "unix socket path (overrides config)")
	flag.Parse()

	if *configPath == "" {
		slog.Error("--config is required")
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	// CLI flag overrides config file.
	if *socketPath != "" {
		cfg.Socket = *socketPath
	}
	if cfg.Socket == "" {
		slog.Error("socket path is required (set in config or via --socket)")
		os.Exit(2)
	}
	if cfg.MailSessionCmd == "" {
		slog.Error("mail_session_cmd is required in config")
		os.Exit(2)
	}

	authRouter, err := manager.SetupAuth(cfg)
	if err != nil {
		slog.Error("setup auth", "error", err)
		os.Exit(1)
	}

	mgr := manager.New(cfg, authRouter)
	defer mgr.Close()

	srv := grpcserver.New(mgr)

	// Graceful shutdown on SIGTERM/SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		srv.Stop()
	}()

	if err := srv.Serve(cfg.Socket); err != nil {
		slog.Error("server", "error", err)
		os.Exit(1)
	}
}
