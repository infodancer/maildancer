package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
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
	// Collector receives ConnectionOpened/ConnectionClosed as handlers are
	// spawned and reaped. nil disables. Session-level metrics are recorded
	// (interim: dropped) in the handlers themselves.
	Collector metrics.Collector
	Logger    *slog.Logger // nil -> slog.Default()
}

// Dispatcher accepts client connections and spawns one protocol-handler
// subprocess per connection. It never speaks IMAP and never holds session
// state.
type Dispatcher struct {
	srv *connfork.Server
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
		listeners = append(listeners, connfork.Listener{Address: lc.Address, Mode: string(lc.Mode)})
	}

	var onStart, onEnd func()
	if cfg.Collector != nil {
		onStart = cfg.Collector.ConnectionOpened
		onEnd = cfg.Collector.ConnectionClosed
	}

	srv := connfork.NewServer(connfork.Config{
		Listeners:   listeners,
		ExecPath:    cfg.ExecPath,
		Args:        handlerArgs(cfg.ConfigPath, tlsCert, tlsKey),
		Env:         handlerEnv,
		SysProcAttr: handlerSysProcAttr(cfg.Config),
		OnConnStart: onStart,
		OnConnEnd:   onEnd,
		MaxConns:    cfg.Config.Limits.MaxConnections,
		Logger:      logger,
	})
	return &Dispatcher{srv: srv}, nil
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
