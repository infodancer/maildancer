package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"

	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/peergate"
)

// Environment variables the dispatcher sets for each handler subprocess.
const (
	EnvClientIP     = "IMAPD_CLIENT_IP"
	EnvListenerMode = "IMAPD_LISTENER_MODE"
)

// DispatcherConfig configures the imapd listener process, the parent half of
// the fork-per-connection model (mail-security-model.md, #179).
type DispatcherConfig struct {
	Config config.Config
	// ExecPath is the imapd binary handlers are spawned from
	// (os.Executable() in production).
	ExecPath string
	// ConfigPath is passed to each handler as --config; use an absolute
	// path since handlers inherit the dispatcher's working directory only
	// incidentally.
	ConfigPath string
	// Metrics is the dispatcher's metrics surface: it receives
	// ConnectionOpened/ConnectionClosed as handlers are spawned and reaped,
	// and aggregates the per-session series each handler reports over the
	// fd-4 pipe at exit (#188). nil disables metrics entirely (no pipe).
	Metrics *metrics.ParentMetrics
	Logger  *slog.Logger // nil -> slog.Default()
}

// Dispatcher accepts client connections and spawns one protocol-handler
// subprocess per connection. It never speaks IMAP and never holds session
// state.
type Dispatcher struct {
	srv *connfork.Server
	// smClient owns the connection the peer gate borrows; nil when the gate
	// is disabled.
	smClient *SessionManagerClient
}

// NewDispatcher validates cfg and builds the dispatcher. imaps listeners
// require TLS material, and configured TLS files must exist -- the dispatcher
// no longer loads the keypair itself (handlers do), so this is the startup
// check that keeps a bad TLS path from failing one connection at a time.
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ExecPath == "" {
		return nil, errors.New("dispatcher requires ExecPath")
	}
	if cfg.ConfigPath == "" {
		return nil, errors.New("dispatcher requires ConfigPath")
	}

	tlsCert := cfg.Config.TLS.CertFile
	tlsKey := cfg.Config.TLS.KeyFile
	if (tlsCert == "") != (tlsKey == "") {
		return nil, errors.New("tls cert_file and key_file must be set together")
	}
	for _, lc := range cfg.Config.Listeners {
		if lc.Mode == config.ModeImaps && tlsCert == "" {
			return nil, fmt.Errorf("listener %s: imaps requires tls cert_file and key_file", lc.Address)
		}
	}
	for _, f := range []string{tlsCert, tlsKey} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("tls material not readable: %w", err)
		}
	}

	listeners := make([]connfork.Listener, 0, len(cfg.Config.Listeners))
	for _, lc := range cfg.Config.Listeners {
		// Every imapd listener is auth-facing: authentication is the point of
		// the protocol on both 143 and 993 (#225).
		listeners = append(listeners, connfork.Listener{
			Address:    lc.Address,
			Mode:       string(lc.Mode),
			AuthFacing: true,
		})
	}

	var onStart, onEnd func()
	var reportSink func(io.Reader) error
	var onGateVerdict func(string)
	var onTarpitStart, onTarpitEnd, onTarpitRejected func()
	var onCache func(bool)
	var onConnRate func(string)
	if cfg.Metrics != nil {
		pm := cfg.Metrics
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
	// to happen before a handler exists at all.
	gate, smClient, err := newPeerGate(cfg.Config, onCache, onConnRate, logger)
	if err != nil {
		return nil, err
	}

	srv := connfork.NewServer(connfork.Config{
		Listeners:        listeners,
		ExecPath:         cfg.ExecPath,
		Args:             handlerArgs(cfg.ConfigPath, tlsCert, tlsKey),
		Env:              handlerEnv,
		SysProcAttr:      handlerSysProcAttr(cfg.Config),
		OnConnStart:      onStart,
		OnConnEnd:        onEnd,
		ReportSink:       reportSink,
		MaxConns:         cfg.Config.Limits.MaxConnections,
		Gate:             gate,
		GateTimeout:      gate.GateTimeout(),
		MaxTarpit:        gate.MaxTarpit(),
		StrictGate:       gate.StrictGate(),
		OnGateVerdict:    onGateVerdict,
		OnTarpitStart:    onTarpitStart,
		OnTarpitEnd:      onTarpitEnd,
		OnTarpitRejected: onTarpitRejected,
		Logger:           logger,
	})
	return &Dispatcher{srv: srv, smClient: smClient}, nil
}

// newPeerGate builds the accept-time gate, returning the session-manager client
// whose connection it borrows so the dispatcher can close it on shutdown.
// Returns (nil, nil, nil) when the gate is disabled.
func newPeerGate(cfg config.Config, onCache func(bool), onConnRate func(string), logger *slog.Logger) (*peergate.Gate, *SessionManagerClient, error) {
	if !cfg.PeerGate.IsEnabled() {
		logger.Info("accept-time peer gate disabled")
		return nil, nil, nil
	}
	if !cfg.SessionManager.IsEnabled() {
		// Not an error: the gate has nothing to ask. The daemon cannot run
		// without session-manager anyway, and that is validated elsewhere.
		return nil, nil, nil
	}

	smClient, err := NewSessionManagerClient(cfg.SessionManager, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("peer gate session-manager client: %w", err)
	}

	gate, err := peergate.New(cfg.PeerGate, smClient.Conn(),
		peergate.Metrics{OnCache: onCache, OnConnRate: onConnRate}, logger)
	if err != nil {
		_ = smClient.Close()
		return nil, nil, err
	}

	logger.Info("accept-time peer gate enabled",
		slog.String("gate_timeout", gate.GateTimeout().String()),
		slog.Int("max_tarpit", gate.MaxTarpit()),
		slog.Bool("strict_gate", gate.StrictGate()),
		slog.Int("conn_rate_threshold", cfg.PeerGate.ConnRateThreshold),
		slog.String("conn_rate_window", cfg.PeerGate.ConnRateWindow.String()),
		slog.Any("allowlist", cfg.PeerGate.Allowlist))
	return gate, smClient, nil
}

// handlerSysProcAttr builds the SysProcAttr for handler subprocesses. When
// handler_uid is configured the handler is spawned directly under those
// credentials (the dispatcher holds the privilege; the child never calls
// setuid/setgid itself). A zero handler_uid returns nil: no drop, handlers
// inherit the dispatcher's credentials.
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

// Run accepts connections on all configured listeners until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) error {
	defer func() {
		if d.smClient != nil {
			if err := d.smClient.Close(); err != nil {
				slog.Debug("peer gate client close", "error", err)
			}
		}
	}()
	return d.srv.Run(ctx)
}

// handlerArgs builds the handler argv tail. The effective TLS paths are
// forwarded as flags so listener-level -tls-cert/-tls-key overrides survive
// the handler's config re-read (imapd has no env overlay; the flag plumbing
// already exists and is tested).
func handlerArgs(configPath, tlsCert, tlsKey string) []string {
	args := []string{"protocol-handler", "--config", configPath}
	if tlsCert != "" {
		args = append(args, "--tls-cert", tlsCert, "--tls-key", tlsKey)
	}
	return args
}

// handlerEnv builds the handler subprocess environment: per-connection
// metadata plus a minimal inherited base.
func handlerEnv(clientIP, mode string) []string {
	env := []string{
		EnvClientIP + "=" + clientIP,
		EnvListenerMode + "=" + mode,
	}
	for _, k := range []string{"PATH", "HOME", "USER", "TMPDIR", "TMP", "TEMP"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
