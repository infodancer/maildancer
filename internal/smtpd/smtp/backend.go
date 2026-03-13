package smtp

import (
	"log/slog"
	"net"

	"github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/oauth"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// Backend implements the go-smtp Backend interface.
// It creates new sessions for each connection.
type Backend struct {
	hostname            string
	delivery            msgstore.DeliveryAgent       // legacy: direct or GrpcDeliveryAgent
	smDelivery          *SessionManagerDeliveryAgent // session-manager: takes priority over delivery
	authAgent           auth.AuthenticationAgent
	authRouter          *domain.AuthRouter
	oauthAgent          oauth.Agent
	domainProvider      domain.DomainProvider
	spamChecker         spamcheck.Checker
	spamConfig          config.SpamCheckConfig
	rejectionMode       config.RejectionMode
	spamtrapLearner     *spamtrapLearner
	spamtrapRateLimiter *ipRateLimiter
	notifier            *Notifier
	collector           metrics.Collector
	maxRecipients       int
	maxMessageSize      int64
	tempDir             string
	logger              *slog.Logger
}

// BackendConfig holds configuration for creating a Backend.
type BackendConfig struct {
	Hostname       string
	Delivery       msgstore.DeliveryAgent       // legacy delivery agent
	SMDelivery     *SessionManagerDeliveryAgent // session-manager delivery agent (preferred)
	AuthAgent      auth.AuthenticationAgent
	AuthRouter     *domain.AuthRouter
	OAuthAgent     oauth.Agent
	DomainProvider domain.DomainProvider
	SpamChecker    spamcheck.Checker
	SpamConfig     config.SpamCheckConfig
	RejectionMode  config.RejectionMode
	SpamtrapConfig config.SpamtrapConfig
	Notifier       *Notifier
	Collector      metrics.Collector
	MaxRecipients  int
	MaxMessageSize int64
	// TempDir is the directory for temporary message files during DATA.
	// Should be on the same filesystem as the mail store to enable atomic renames.
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
		hostname:       cfg.Hostname,
		delivery:       cfg.Delivery,
		smDelivery:     cfg.SMDelivery,
		authAgent:      cfg.AuthAgent,
		authRouter:     cfg.AuthRouter,
		oauthAgent:     cfg.OAuthAgent,
		domainProvider: cfg.DomainProvider,
		spamChecker:    cfg.SpamChecker,
		spamConfig:     cfg.SpamConfig,
		rejectionMode:  cfg.RejectionMode,
		notifier:       cfg.Notifier,
		collector:      cfg.Collector,
		maxRecipients:  cfg.MaxRecipients,
		maxMessageSize: cfg.MaxMessageSize,
		tempDir:        cfg.TempDir,
		logger:         logger,
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

	return &Session{
		backend:  b,
		conn:     c,
		clientIP: clientIP,
		logger:   b.logger.With(slog.String("client_ip", clientIP)),
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
