package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/passwd" // Register passwd backend
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/infodancer/maildancer/internal/pop3d/server"
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

	// Create authentication agent
	authAgent, err := msgstore.OpenAuthAgent(msgstore.AuthAgentConfig{
		Type:              cfg.Auth.Type,
		CredentialBackend: cfg.Auth.CredentialBackend,
		KeyBackend:        cfg.Auth.KeyBackend,
		Options:           cfg.Auth.Options,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating auth agent: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := authAgent.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "error closing auth agent: %v\n", err)
		}
	}()

	// Create server
	srv, err := server.New(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
	}

	// Set POP3 protocol handler
	handler := pop3.Handler(cfg.Hostname, authAgent, srv.TLSConfig())
	srv.SetHandler(handler)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		srv.Logger().Info("received shutdown signal")
		cancel()
	}()

	// Run server
	srv.Logger().Info("POP3 server starting", "hostname", cfg.Hostname)
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	srv.Logger().Info("POP3 server stopped")
}
