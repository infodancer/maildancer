package smtp

import (
	"log/slog"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/auth/oauth"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
	"github.com/redis/go-redis/v9"
)

// Backend implements the go-smtp Backend interface.
// It creates new sessions for each connection.
type Backend struct {
	hostname            string
	smDelivery          *SessionManagerDeliveryAgent // session-manager: sole delivery agent
	oauthAgent          oauth.Agent
	spamChecker         spamcheck.Checker
	spamConfig          config.SpamCheckConfig
	rejectionMode       config.RejectionMode
	spamtrapLearner     *spamtrapLearner
	spamtrapRateLimiter *ipRateLimiter
	senderRateLimiter   senderLimiter
	maxSendsPerHour     int // global default; per-domain overrides via loginResult
	notifier            *Notifier
	collector           metrics.Collector
	maxRecipients       int
	maxMessageSize      int64
	tempDir             string
	logger              *slog.Logger
}

// BackendConfig holds configuration for creating a Backend.
type BackendConfig struct {
	Hostname        string
	SMDelivery      *SessionManagerDeliveryAgent // session-manager delivery agent
	OAuthAgent      oauth.Agent
	SpamChecker     spamcheck.Checker
	SpamConfig      config.SpamCheckConfig
	RejectionMode   config.RejectionMode
	SpamtrapConfig  config.SpamtrapConfig
	MaxSendsPerHour int
	RedisClient     *redis.Client // shared Redis for cross-subprocess rate limiting
	Notifier        *Notifier
	Collector       metrics.Collector
	MaxRecipients   int
	MaxMessageSize  int64
	// TempDir is the directory for temporary message files during DATA.
	// Defaults to os.TempDir() if empty.
	TempDir string
	Logger  *slog.Logger
}

// NewBackend creates a new Backend with the given configuration.
func NewBackend(cfg BackendConfig) *Backend {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	b := &Backend{
		hostname:        cfg.Hostname,
		smDelivery:      cfg.SMDelivery,
		oauthAgent:      cfg.OAuthAgent,
		spamChecker:     cfg.SpamChecker,
		spamConfig:      cfg.SpamConfig,
		rejectionMode:   cfg.RejectionMode,
		notifier:        cfg.Notifier,
		collector:       cfg.Collector,
		maxRecipients:   cfg.MaxRecipients,
		maxMessageSize:  cfg.MaxMessageSize,
		maxSendsPerHour: cfg.MaxSendsPerHour,
		tempDir:         cfg.TempDir,
		logger:          logger,
	}

	if cfg.RedisClient != nil {
		b.senderRateLimiter = newRedisRateLimiter(
			cfg.RedisClient, time.Hour, "smtpd:sendrate:")
		logger.Info("sender rate limiting enabled",
			"default_max_sends_per_hour", cfg.MaxSendsPerHour)
	}

	if cfg.SpamtrapConfig.Enabled && cfg.SpamtrapConfig.ControllerURL != "" {
		b.spamtrapLearner = newSpamtrapLearner(cfg.SpamtrapConfig.ControllerURL, cfg.SpamtrapConfig.Password)
		b.spamtrapRateLimiter = newIPRateLimiter(cfg.SpamtrapConfig.GetMaxLearnsPerIPPerHour())
		logger.Info("spamtrap auto-learning enabled",
			"controller_url", cfg.SpamtrapConfig.ControllerURL,
			"max_learns_per_ip_per_hour", cfg.SpamtrapConfig.GetMaxLearnsPerIPPerHour())
	}

	return b
}

// NewSession is called for each new connection.
// It implements the smtp.Backend interface.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// Record connection opened
	if b.collector != nil {
		b.collector.ConnectionOpened()
	}

	clientIP := extractIPFromConn(c.Conn())
	remoteAddr := ""
	if c.Conn() != nil && c.Conn().RemoteAddr() != nil {
		remoteAddr = c.Conn().RemoteAddr().String()
	}

	return &Session{
		backend:  b,
		conn:     c,
		clientIP: clientIP,
		logger:   logging.WithConnection(b.logger, remoteAddr),
	}, nil
}

// extractIPFromConn extracts the IP address string from a net.Conn.
func extractIPFromConn(conn net.Conn) string {
	if conn == nil {
		return ""
	}

	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}

	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}
