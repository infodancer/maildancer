package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"

	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/peergate"
	"github.com/infodancer/maildancer/internal/smclient"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
)

// SubprocessServer listens on configured TCP ports and spawns a protocol-handler
// subprocess per accepted connection, via the shared connfork dispatcher the
// smtpd implementation was originally generalized into (#189). Each subprocess
// receives the raw TCP socket as fd 3, the metrics-report pipe as fd 4 when
// metrics are enabled, and handles exactly one SMTP session before exiting.
//
// The subprocess is invoked as:
//
//	smtpd protocol-handler --config <configPath>
//
// Connection metadata is passed via environment variables:
//
//	SMTPD_CLIENT_IP     - remote IP address of the connecting client
//	SMTPD_LISTENER_MODE - listener mode (smtp/submission/smtps/alt)
type SubprocessServer struct {
	srv *connfork.Server
	// gateClient owns the connection the peer gate borrows; nil when the gate
	// is disabled.
	gateClient *smclient.Client
}

// NewSubprocessServer creates a SubprocessServer from the listener's
// effective configuration (listeners, handler credentials, TLS overrides).
// execPath is the path to the smtpd binary (use os.Executable()).
// configPath is passed to each subprocess as the --config flag value.
// parentMetrics is the aggregation surface for per-connection metrics; pass nil
// when metrics are disabled (no report pipe is created).
func NewSubprocessServer(cfg config.Config, execPath, configPath string, parentMetrics *metrics.ParentMetrics, logger *slog.Logger) (*SubprocessServer, error) {
	listeners := make([]connfork.Listener, 0, len(cfg.Listeners))
	for _, lc := range cfg.Listeners {
		// Submission (587) and SMTPS (465) exist to authenticate clients;
		// plain SMTP (25) exists to receive mail from other MTAs and nobody
		// authenticates there. Auth-derived bans are enforced only on the
		// former, because refusing inbound mail on the strength of an
		// authentication signal destroys a third party's message (#225).
		authFacing := lc.Mode == config.ModeSubmission || lc.Mode == config.ModeSmtps
		listeners = append(listeners, connfork.Listener{
			Address:    lc.Address,
			Mode:       string(lc.Mode),
			AuthFacing: authFacing,
		})
	}

	var onStart, onEnd func()
	var reportSink func(io.Reader) error
	var onGateVerdict func(string)
	var onTarpitStart, onTarpitEnd, onTarpitRejected func()
	var onCache func(bool)
	var onConnRate func(string)
	if parentMetrics != nil {
		pm := parentMetrics
		onStart = pm.ConnectionOpened
		onEnd = pm.ConnectionClosed
		reportSink = pm.Sink()
		onGateVerdict = pm.GateVerdict
		onTarpitStart = pm.TarpitStarted
		onTarpitEnd = pm.TarpitEnded
		onTarpitRejected = pm.TarpitRejected
		onCache = pm.GateCacheResult
		onConnRate = pm.ConnRate
	}

	// The accept-time peer gate (#206). The dispatcher opens its own
	// session-manager connection: handlers are one-shot subprocesses, so a
	// verdict cache only pays off in the long-lived parent, and the check has
	// to happen before a handler exists at all. Most inbound connections never
	// authenticate, so smtpd is where an auth-path-only check misses the most.
	gate, gateClient, err := newPeerGate(cfg, onCache, onConnRate, logger)
	if err != nil {
		return nil, err
	}

	return &SubprocessServer{
		gateClient: gateClient,
		srv: connfork.NewServer(connfork.Config{
			Listeners: listeners,
			ExecPath:  execPath,
			Args:      []string{"protocol-handler", "--config", configPath},
			Env: func(clientIP, mode string) []string {
				return handlerEnv(cfg, clientIP, config.ListenerMode(mode))
			},
			SysProcAttr:      handlerSysProcAttr(cfg),
			OnConnStart:      onStart,
			OnConnEnd:        onEnd,
			ReportSink:       reportSink,
			Gate:             gate,
			GateTimeout:      gate.GateTimeout(),
			MaxTarpit:        gate.MaxTarpit(),
			StrictGate:       gate.StrictGate(),
			OnGateVerdict:    onGateVerdict,
			OnTarpitStart:    onTarpitStart,
			OnTarpitEnd:      onTarpitEnd,
			OnTarpitRejected: onTarpitRejected,
			Logger:           logger,
		}),
	}, nil
}

// newPeerGate builds the accept-time gate, returning the session-manager client
// whose connection it borrows so the dispatcher can close it on shutdown.
// Returns (nil, nil, nil) when the gate is disabled.
//
// It dials through internal/smclient rather than reusing
// SessionManagerDeliveryAgent: the delivery agent is the handler's tool and
// logs itself as such, while this connection exists only to ask CheckPeer.
func newPeerGate(cfg config.Config, onCache func(bool), onConnRate func(string), logger *slog.Logger) (*peergate.Gate, *smclient.Client, error) {
	if !cfg.PeerGate.IsEnabled() {
		logger.Info("accept-time peer gate disabled")
		return nil, nil, nil
	}
	if !cfg.SessionManager.IsEnabled() {
		return nil, nil, nil
	}

	client, err := smclient.New(smclient.Config{
		Socket:     cfg.SessionManager.Socket,
		Address:    cfg.SessionManager.Address,
		CACert:     cfg.SessionManager.CACert,
		ClientCert: cfg.SessionManager.ClientCert,
		ClientKey:  cfg.SessionManager.ClientKey,
	}, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("peer gate session-manager client: %w", err)
	}

	gate, err := peergate.New(cfg.PeerGate, client.Conn(),
		peergate.Metrics{OnCache: onCache, OnConnRate: onConnRate}, logger)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}

	logger.Info("accept-time peer gate enabled",
		slog.String("gate_timeout", gate.GateTimeout().String()),
		slog.Int("max_tarpit", gate.MaxTarpit()),
		slog.Bool("strict_gate", gate.StrictGate()),
		slog.Int("conn_rate_threshold", cfg.PeerGate.ConnRateThreshold),
		slog.String("conn_rate_window", cfg.PeerGate.ConnRateWindow.String()),
		slog.Any("allowlist", cfg.PeerGate.Allowlist))
	return gate, client, nil
}

// Run starts accept loops on all configured ports and blocks until ctx is cancelled.
func (s *SubprocessServer) Run(ctx context.Context) error {
	defer func() {
		if s.gateClient != nil {
			if err := s.gateClient.Close(); err != nil {
				slog.Debug("peer gate client close", "error", err)
			}
		}
	}()
	return s.srv.Run(ctx)
}

// handlerSysProcAttr builds the SysProcAttr for protocol-handler subprocesses.
// When handler_uid is configured the handler is spawned directly under those
// credentials (the listener holds the privilege; the child never calls
// setuid/setgid itself, matching the session-manager -> mail-session model).
// A zero handler_uid returns nil: no drop, handlers inherit the listener's
// credentials, which keeps dev and rootless setups working.
func handlerSysProcAttr(cfg config.Config) *syscall.SysProcAttr {
	if cfg.HandlerUID == 0 {
		return nil
	}
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    cfg.HandlerUID,
			Gid:    cfg.HandlerGID,
			Groups: cfg.HandlerGroups,
		},
		Setpgid: true,
	}
}

// handlerEnv builds the protocol-handler subprocess environment: connection
// metadata, the listener's effective TLS material, and a minimal inherited
// base. The TLS paths are passed explicitly because the handler re-reads the
// config file itself -- without this, -tls-cert/-tls-key (or env) overrides
// given to the listener would never reach the handler.
func handlerEnv(cfg config.Config, clientIP string, mode config.ListenerMode) []string {
	env := []string{
		"SMTPD_CLIENT_IP=" + clientIP,
		"SMTPD_LISTENER_MODE=" + string(mode),
	}
	if cfg.TLS.CertFile != "" {
		env = append(env, "SMTPD_TLS_CERT_FILE="+cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "" {
		env = append(env, "SMTPD_TLS_KEY_FILE="+cfg.TLS.KeyFile)
	}
	return append(env, inheritEnv("PATH", "HOME", "USER", "TMPDIR", "TMP", "TEMP")...)
}

// inheritEnv returns "KEY=VALUE" strings for the named env vars that are set.
func inheritEnv(keys ...string) []string {
	var env []string
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
