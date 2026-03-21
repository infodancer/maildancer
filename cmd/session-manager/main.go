package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/session-manager/certutil"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/grpcserver"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"

	// Register storage drivers used by the domain provider.
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cert" {
		handleCert(os.Args[2:])
		return
	}

	runServe()
}

func runServe() {
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

	logger := logging.NewLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	if *socketPath != "" {
		cfg.Socket = *socketPath
	}
	if cfg.Socket == "" && cfg.Listen == "" {
		slog.Error("socket or listen address required (set in config or via --socket)")
		os.Exit(2)
	}
	if cfg.MailSessionCmd == "" {
		slog.Error("mail_session_cmd is required in config")
		os.Exit(2)
	}
	if cfg.Listen != "" && cfg.TLS.CACert == "" {
		slog.Error("mTLS is required for network mode (set tls.ca_cert, tls.server_cert, tls.server_key)")
		os.Exit(2)
	}

	authRouter, domainProvider, err := manager.SetupAuth(cfg)
	if err != nil {
		slog.Error("setup auth", "error", err)
		os.Exit(1)
	}

	mc, metricsSrv := metrics.New(metrics.Config{
		Enabled: cfg.Metrics.Enabled,
		Address: cfg.Metrics.Address,
		Path:    cfg.Metrics.Path,
	})

	mgr := manager.New(cfg, authRouter, domainProvider, mc)
	defer mgr.Close()

	srv, err := grpcserver.New(mgr, cfg, mc)
	if err != nil {
		slog.Error("create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := metricsSrv.Start(ctx); err != nil {
			slog.Error("metrics server", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsSrv.Shutdown(shutdownCtx)
		srv.Stop()
	}()

	// Prefer TCP+mTLS when listen is configured; fall back to unix socket.
	if cfg.Listen != "" {
		if err := srv.ServeTCP(cfg.Listen); err != nil {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
	} else {
		if err := srv.ServeUnix(cfg.Socket); err != nil {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
	}
}

func handleCert(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: session-manager cert <ca|issue>")
		os.Exit(2)
	}

	switch args[0] {
	case "ca":
		handleCertCA(args[1:])
	case "issue":
		handleCertIssue(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown cert subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: session-manager cert <ca|issue>")
		os.Exit(2)
	}
}

func handleCertCA(args []string) {
	fs := flag.NewFlagSet("cert ca", flag.ExitOnError)
	caCert := fs.String("ca-cert", "ca.crt", "output path for CA certificate")
	caKey := fs.String("ca-key", "ca.key", "output path for CA private key")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if err := certutil.GenerateCA(*caCert, *caKey, 0); err != nil {
		slog.Error("generate CA", "error", err)
		os.Exit(1)
	}

	fmt.Printf("CA certificate: %s\n", *caCert)
	fmt.Printf("CA private key: %s\n", *caKey)
}

func handleCertIssue(args []string) {
	fs := flag.NewFlagSet("cert issue", flag.ExitOnError)
	caCert := fs.String("ca-cert", "ca.crt", "path to CA certificate")
	caKey := fs.String("ca-key", "ca.key", "path to CA private key")
	name := fs.String("name", "", "certificate common name (required, e.g. 'smtpd')")
	certOut := fs.String("cert", "", "output path for certificate (default: <name>.crt)")
	keyOut := fs.String("key", "", "output path for private key (default: <name>.key)")
	server := fs.Bool("server", false, "issue a server certificate (default: client)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "--name is required")
		os.Exit(2)
	}
	if *certOut == "" {
		*certOut = *name + ".crt"
	}
	if *keyOut == "" {
		*keyOut = *name + ".key"
	}

	if err := certutil.IssueCert(*caCert, *caKey, *certOut, *keyOut, *name, *server, 0); err != nil {
		slog.Error("issue certificate", "error", err)
		os.Exit(1)
	}

	kind := "client"
	if *server {
		kind = "server"
	}
	fmt.Printf("Issued %s certificate for %q\n", kind, *name)
	fmt.Printf("Certificate: %s\n", *certOut)
	fmt.Printf("Private key: %s\n", *keyOut)
}
