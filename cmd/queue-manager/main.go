// Command queue-manager drives the infodancer mail queue retry loop.
// It scans the queue directory for pending envelopes, applies exponential
// backoff based on envelope file mtime, and invokes mail-remote for delivery.
//
// Usage:
//
//	queue-manager [flags]
//
// Flags:
//
//	--queue            path    Root of the mail queue directory (required).
//	--binary           path    Path to the mail-remote binary (default: mail-remote in PATH).
//	--config           path    Shared TOML config file (passed to mail-remote as --config).
//	--smarthost        h:port  Global fallback smarthost (used when no per-domain config found).
//	--smarthost-user   u       Global fallback smarthost user.
//	--domain-config    path    Base directory for per-domain config files (enables per-domain outbound routing).
//	--interval         dur     How often to scan the queue (default: 1m).
//	--message-ttl      dur     Default message TTL for backoff calculation (default: 168h).
//	--hostname         name    Reporting MTA hostname for DSN headers (overrides TOML; default: os.Hostname).
//	--rate-limit       n       Default messages per hour per domain; 0 = unlimited (overrides TOML).
//	--rate-limit-burst n       Default burst per domain (overrides TOML).
//	--once                     Scan once and exit (useful for cron / testing).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/queue-manager/config"
	"github.com/infodancer/maildancer/internal/queue-manager/metrics"
	"github.com/infodancer/maildancer/internal/queue-manager/scheduler"
)

func main() {
	if err := run(); err != nil {
		slog.Error("queue-manager", "error", err)
		os.Exit(1)
	}
}

func run() error {
	queueDir := flag.String("queue", "", "root of the mail queue directory (required)")
	binary := flag.String("binary", "mail-remote", "path to the mail-remote binary")
	configPath := flag.String("config", "", "shared TOML config file (passed to mail-remote as --config)")
	smarthostAddr := flag.String("smarthost", "", "SMTP smarthost address (host:port)")
	smarthostUser := flag.String("smarthost-user", "", "SMTP AUTH username for smarthost")
	domainConfig := flag.String("domain-config", "", "base directory for per-domain config files (enables per-domain outbound routing)")
	interval := flag.Duration("interval", time.Minute, "queue scan interval")
	messageTTL := flag.Duration("message-ttl", 7*24*time.Hour, "default message TTL (for backoff calculation)")
	hostname := flag.String("hostname", "", "reporting MTA hostname for DSN headers (overrides TOML)")
	rateLimitMPH := flag.Int("rate-limit", 0, "default messages per hour per domain; 0 = unlimited (overrides TOML)")
	rateLimitBurst := flag.Int("rate-limit-burst", 0, "default burst per domain (overrides TOML)")
	once := flag.Bool("once", false, "scan once and exit")
	flag.Parse()

	if *queueDir == "" {
		return fmt.Errorf("--queue is required")
	}

	// Load config from the shared TOML file.
	fileCfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI flags override TOML values when explicitly set.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "hostname":
			fileCfg.Hostname = *hostname
		case "rate-limit":
			fileCfg.RateLimit.MessagesPerHour = *rateLimitMPH
		case "rate-limit-burst":
			fileCfg.RateLimit.Burst = *rateLimitBurst
		case "domain-config":
			fileCfg.DomainConfigPath = *domainConfig
		}
	})

	// Fall back to os.Hostname if not configured.
	if fileCfg.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			slog.Warn("could not determine hostname", "error", err)
			h = "localhost"
		}
		fileCfg.Hostname = h
	}

	slog.Info("queue-manager config",
		"hostname", fileCfg.Hostname,
		"domain_config_path", fileCfg.DomainConfigPath,
		"dsn_enabled", fileCfg.DSN.Enabled,
		"session_manager_socket", fileCfg.SessionManager.Socket,
		"rate_limit_mph", fileCfg.RateLimit.MessagesPerHour,
		"rate_limit_burst", fileCfg.RateLimit.Burst,
		"rate_limit_domains", len(fileCfg.RateLimit.Domains),
		"metrics_enabled", fileCfg.Metrics.Enabled)

	// Initialize metrics.
	metricsCfg := metrics.Config{
		Enabled: fileCfg.Metrics.Enabled,
		Address: fileCfg.Metrics.Address,
		Path:    fileCfg.Metrics.Path,
	}
	collector, metricsServer := metrics.New(metricsCfg)

	// Start metrics server in the background.
	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()
	go func() {
		if err := metricsServer.Start(metricsCtx); err != nil {
			slog.Error("metrics server error", "error", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsServer.Shutdown(shutdownCtx)
	}()

	cfg := scheduler.Config{
		QueueDir:         *queueDir,
		Binary:           *binary,
		ConfigPath:       *configPath,
		SmarthostAddr:    *smarthostAddr,
		SmarthostUser:    *smarthostUser,
		DomainConfigPath: fileCfg.DomainConfigPath,
		Interval:         *interval,
		MessageTTL:       *messageTTL,
		Hostname:         fileCfg.Hostname,
		RateLimit:        fileCfg.RateLimit,
		DSN:              fileCfg.DSN,
		SessionManager:   fileCfg.SessionManager,
		Collector:        collector,
	}

	sched, err := scheduler.New(cfg)
	if err != nil {
		return fmt.Errorf("creating scheduler: %w", err)
	}
	defer func() { _ = sched.Close() }()

	if *once {
		return sched.RunOnce()
	}

	sched.Run()
	return nil
}
