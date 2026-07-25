package smtp

import (
	"context"
	"io"
	"log/slog"
	"os"
	"syscall"

	"github.com/infodancer/maildancer/internal/connfork"
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
}

// NewSubprocessServer creates a SubprocessServer from the listener's
// effective configuration (listeners, handler credentials, TLS overrides).
// execPath is the path to the smtpd binary (use os.Executable()).
// configPath is passed to each subprocess as the --config flag value.
// parentMetrics is the aggregation surface for per-connection metrics; pass nil
// when metrics are disabled (no report pipe is created).
func NewSubprocessServer(cfg config.Config, execPath, configPath string, parentMetrics *metrics.ParentMetrics, logger *slog.Logger) *SubprocessServer {
	listeners := make([]connfork.Listener, 0, len(cfg.Listeners))
	for _, lc := range cfg.Listeners {
		listeners = append(listeners, connfork.Listener{Address: lc.Address, Mode: string(lc.Mode)})
	}

	var onStart, onEnd func()
	var reportSink func(io.Reader) error
	if parentMetrics != nil {
		pm := parentMetrics
		onStart = pm.ConnectionOpened
		onEnd = pm.ConnectionClosed
		reportSink = pm.Sink()
	}

	return &SubprocessServer{srv: connfork.NewServer(connfork.Config{
		Listeners: listeners,
		ExecPath:  execPath,
		Args:      []string{"protocol-handler", "--config", configPath},
		Env: func(clientIP, mode string) []string {
			return handlerEnv(cfg, clientIP, config.ListenerMode(mode))
		},
		SysProcAttr: handlerSysProcAttr(cfg),
		OnConnStart: onStart,
		OnConnEnd:   onEnd,
		ReportSink:  reportSink,
		Logger:      logger,
	})}
}

// Run starts accept loops on all configured ports and blocks until ctx is cancelled.
func (s *SubprocessServer) Run(ctx context.Context) error {
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
