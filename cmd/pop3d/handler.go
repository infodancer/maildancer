package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"

	_ "github.com/infodancer/maildancer/auth/passwd"      // Register passwd auth backend
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir storage backend
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
)

// connFD is the file descriptor number used to pass the TCP socket from the
// listener parent to the protocol-handler subprocess. It is the first entry in
// cmd.ExtraFiles, which the OS maps to fd 3 (stdin=0, stdout=1, stderr=2).
const connFD = 3

func runProtocolHandler() {
	flags := config.ParseFlags()

	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.LogLevel)

	// Connection metadata supplied by the parent listener process.
	clientIP := os.Getenv("POP3D_CLIENT_IP")
	listenerMode := config.ListenerMode(os.Getenv("POP3D_LISTENER_MODE"))
	if listenerMode == "" {
		listenerMode = config.ModePop3
	}

	logger.Debug("protocol-handler started",
		"client_ip", clientIP,
		"mode", string(listenerMode))

	// Load TLS configuration (needed for STLS on POP3 and for implicit TLS on POP3S).
	var tlsConfig *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "protocol-handler: error loading TLS certificate: %v\n", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   cfg.TLS.MinTLSVersion(),
		}
	}

	// Resolve config path to an absolute path.
	configPath, err := filepath.Abs(flags.ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: resolving config path: %v\n", err)
		os.Exit(1)
	}

	// Build the full auth/delivery stack. Each subprocess gets its own stack
	// instance; there is no shared state with the parent listener process.
	stack, err := pop3.NewStack(pop3.StackConfig{
		Config:     cfg,
		ConfigPath: configPath,
		TLSConfig:  tlsConfig,
		Collector:  &metrics.NoopCollector{},
		Logger:     logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error creating stack: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := stack.Close(); err != nil {
			logger.Error("error closing stack", "error", err)
		}
	}()

	// Reconstruct the TCP connection from the fd passed by the parent.
	// ExtraFiles[0] maps to fd 3 in the child process.
	connFile := os.NewFile(uintptr(connFD), "pop3-conn")
	if connFile == nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: fd %d not available\n", connFD)
		os.Exit(1)
	}
	netConn, err := net.FileConn(connFile)
	connFile.Close() // done with the os.File wrapper; netConn holds its own dup
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol-handler: error reconstructing connection: %v\n", err)
		os.Exit(1)
	}

	// Run exactly one POP3 session then exit.
	if err := stack.RunSingleConn(netConn, listenerMode, tlsConfig); err != nil {
		logger.Debug("session ended", "error", err.Error())
	}
}
