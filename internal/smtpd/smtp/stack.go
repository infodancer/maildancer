package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
	goredis "github.com/redis/go-redis/v9"
)

// Stack owns all components of a running smtpd instance and manages their lifecycle.
type Stack struct {
	Server  *Server
	closers []io.Closer
	logger  *slog.Logger
}

// StackConfig groups config needed to build a Stack.
// TLSConfig and SpamChecker are caller-supplied (main.go builds them; tests omit them).
type StackConfig struct {
	Config      config.Config
	TLSConfig   *tls.Config
	SpamChecker spamcheck.Checker
	SpamConfig  config.SpamCheckConfig
	Collector   metrics.Collector // nil → NoopCollector
	Logger      *slog.Logger      // nil → slog.Default()
}

// NewStack creates a Stack from the given configuration, wiring up all components.
func NewStack(cfg StackConfig) (*Stack, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	collector := cfg.Collector
	if collector == nil {
		collector = &metrics.NoopCollector{}
	}

	s := &Stack{logger: logger}

	// Session-manager is required -- it handles auth, delivery, and recipient validation.
	if !cfg.Config.SessionManager.IsEnabled() {
		return nil, fmt.Errorf("session-manager configuration is required")
	}

	smDelivery, err := NewSessionManagerDeliveryAgent(cfg.Config.SessionManager, logger)
	if err != nil {
		s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
		return nil, err
	}
	s.closers = append(s.closers, smDelivery)

	// Create shared Redis client for notifications and rate limiting.
	var redisClient *goredis.Client
	var notifier *Notifier
	if cfg.Config.Redis.URL != "" {
		opts, err := goredis.ParseURL(cfg.Config.Redis.URL)
		if err != nil {
			s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
			return nil, err
		}
		if cfg.Config.Redis.Password != "" {
			opts.Password = cfg.Config.Redis.Password
		}
		redisClient = goredis.NewClient(opts)
		notifier = NewNotifierFromClient(redisClient, logger)
		s.closers = append(s.closers, notifier)
		logger.Info("redis enabled", "url", cfg.Config.Redis.URL)
	}

	backend := NewBackend(BackendConfig{
		Hostname:        cfg.Config.Hostname,
		SMDelivery:      smDelivery,
		SpamChecker:     cfg.SpamChecker,
		SpamConfig:      cfg.SpamConfig,
		RejectionMode:   cfg.Config.GetRejectionMode(),
		SpamtrapConfig:  cfg.Config.Spamtrap,
		MaxSendsPerHour: cfg.Config.Limits.MaxSendsPerHour,
		RedisClient:     redisClient,
		Notifier:        notifier,
		Collector:       collector,
		MaxRecipients:   cfg.Config.Limits.MaxRecipients,
		MaxMessageSize:  int64(cfg.Config.Limits.MaxMessageSize),
		Logger:          logger,
	})

	srv, err := NewServer(ServerConfig{
		Backend:        backend,
		Listeners:      cfg.Config.Listeners,
		Hostname:       cfg.Config.Hostname,
		TLSConfig:      cfg.TLSConfig,
		ReadTimeout:    cfg.Config.Timeouts.ConnectionTimeout(),
		WriteTimeout:   cfg.Config.Timeouts.ConnectionTimeout(),
		MaxMessageSize: cfg.Config.Limits.MaxMessageSize,
		MaxRecipients:  cfg.Config.Limits.MaxRecipients,
		Logger:         logger,
	})
	if err != nil {
		s.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here
		return nil, err
	}

	s.Server = srv
	return s, nil
}

// Run starts the server and blocks until the context is cancelled.
func (s *Stack) Run(ctx context.Context) error {
	return s.Server.Run(ctx)
}

// Close shuts down all closeable components in reverse registration order.
func (s *Stack) Close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
