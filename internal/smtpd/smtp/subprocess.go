package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// SubprocessServer listens on configured TCP ports and spawns a protocol-handler
// subprocess per accepted connection. Each subprocess receives the raw TCP socket
// as fd 3 and handles exactly one SMTP session before exiting.
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
	cfg        config.Config
	execPath   string
	configPath string
	logger     *slog.Logger
	wg         sync.WaitGroup
}

// NewSubprocessServer creates a SubprocessServer from the listener's
// effective configuration (listeners, handler credentials, TLS overrides).
// execPath is the path to the smtpd binary (use os.Executable()).
// configPath is passed to each subprocess as the --config flag value.
func NewSubprocessServer(cfg config.Config, execPath, configPath string, logger *slog.Logger) *SubprocessServer {
	return &SubprocessServer{
		cfg:        cfg,
		execPath:   execPath,
		configPath: configPath,
		logger:     logger,
	}
}

// Run starts accept loops on all configured ports and blocks until ctx is cancelled.
func (s *SubprocessServer) Run(ctx context.Context) error {
	lns := make([]net.Listener, 0, len(s.cfg.Listeners))
	for _, lc := range s.cfg.Listeners {
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return fmt.Errorf("listen %s: %w", lc.Address, err)
		}
		lns = append(lns, ln)
		s.logger.Info("listening (subprocess mode)",
			slog.String("address", lc.Address),
			slog.String("mode", string(lc.Mode)))
	}

	for i, ln := range lns {
		s.wg.Add(1)
		go func(ln net.Listener, lc config.ListenerConfig) {
			defer s.wg.Done()
			s.acceptLoop(ctx, ln, lc)
		}(ln, s.cfg.Listeners[i])
	}

	<-ctx.Done()
	s.logger.Info("shutting down subprocess server")
	for _, ln := range lns {
		_ = ln.Close()
	}
	s.wg.Wait()
	return ctx.Err()
}

func (s *SubprocessServer) acceptLoop(ctx context.Context, ln net.Listener, lc config.ListenerConfig) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("accept error",
					slog.String("address", lc.Address),
					slog.String("error", err.Error()))
				return
			}
		}
		go s.spawnHandler(conn, lc)
	}
}

// spawnHandler passes conn to a protocol-handler subprocess and reaps it asynchronously.
func (s *SubprocessServer) spawnHandler(conn net.Conn, lc config.ListenerConfig) {
	clientIP := extractIPFromConn(conn)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		s.logger.Error("cannot pass non-TCP connection to subprocess",
			slog.String("type", fmt.Sprintf("%T", conn)))
		_ = conn.Close()
		return
	}

	// File() dups the fd so the subprocess can inherit it independently.
	connFile, err := tcpConn.File()
	if err != nil {
		s.logger.Error("failed to dup connection fd", slog.String("error", err.Error()))
		_ = conn.Close()
		return
	}

	// Parent relinquishes its copy of the socket; subprocess owns it.
	_ = conn.Close()

	cmd := exec.Command(s.execPath, "protocol-handler", "--config", s.configPath)
	cmd.ExtraFiles = []*os.File{connFile} // becomes fd 3 in the child
	cmd.Env = handlerEnv(s.cfg, clientIP, lc.Mode)
	cmd.SysProcAttr = handlerSysProcAttr(s.cfg)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		s.logger.Error("failed to start protocol-handler",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		return
	}
	_ = connFile.Close() // child has the fd; parent closes its dup

	pid := cmd.Process.Pid
	s.logger.Debug("spawned protocol-handler",
		slog.Int("pid", pid),
		slog.String("client_ip", clientIP),
		slog.String("mode", string(lc.Mode)))

	// Reap the subprocess asynchronously to avoid zombies.
	go func() {
		if err := cmd.Wait(); err != nil {
			s.logger.Debug("protocol-handler exited with error",
				slog.Int("pid", pid),
				slog.String("error", err.Error()))
		} else {
			s.logger.Debug("protocol-handler exited", slog.Int("pid", pid))
		}
	}()
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
