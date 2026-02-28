package pop3

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// SubprocessServer accepts TCP connections on configured addresses and spawns a
// protocol-handler subprocess for each one, passing the socket as fd 3 via
// ExtraFiles.
//
// The subprocess is invoked as:
//
//	pop3d protocol-handler --config <configPath>
//
// Connection metadata is passed via environment variables:
//
//	POP3D_CLIENT_IP     - remote IP address of the connecting client
//	POP3D_LISTENER_MODE - listener mode (pop3/pop3s)
type SubprocessServer struct {
	listeners  []config.ListenerConfig
	execPath   string
	configPath string
	logger     *slog.Logger
	wg         sync.WaitGroup
}

// NewSubprocessServer creates a SubprocessServer.
// execPath is the path to the pop3d binary (use os.Executable()).
// configPath is passed to each subprocess as the --config flag value.
func NewSubprocessServer(listeners []config.ListenerConfig, execPath, configPath string, logger *slog.Logger) *SubprocessServer {
	return &SubprocessServer{
		listeners:  listeners,
		execPath:   execPath,
		configPath: configPath,
		logger:     logger,
	}
}

// Run starts accept loops on all configured ports and blocks until ctx is cancelled.
func (s *SubprocessServer) Run(ctx context.Context) error {
	lns := make([]net.Listener, 0, len(s.listeners))
	for _, lc := range s.listeners {
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			for _, l := range lns {
				l.Close()
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
		}(ln, s.listeners[i])
	}

	<-ctx.Done()
	s.logger.Info("shutting down subprocess server")
	for _, ln := range lns {
		ln.Close()
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
	clientIP := extractIPFromAddr(conn.RemoteAddr())

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		s.logger.Error("cannot pass non-TCP connection to subprocess",
			slog.String("type", fmt.Sprintf("%T", conn)))
		conn.Close()
		return
	}

	// File() dups the fd so the subprocess can inherit it independently.
	connFile, err := tcpConn.File()
	if err != nil {
		s.logger.Error("failed to dup connection fd", slog.String("error", err.Error()))
		conn.Close()
		return
	}

	// Parent relinquishes its copy of the socket; subprocess owns it.
	conn.Close()

	cmd := exec.Command(s.execPath, "protocol-handler", "--config", s.configPath)
	cmd.ExtraFiles = []*os.File{connFile} // becomes fd 3 in the child
	cmd.Env = append(
		[]string{
			"POP3D_CLIENT_IP=" + clientIP,
			"POP3D_LISTENER_MODE=" + string(lc.Mode),
		},
		inheritEnv("PATH", "HOME", "USER", "TMPDIR", "TMP", "TEMP")...,
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		s.logger.Error("failed to start protocol-handler",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		connFile.Close()
		return
	}
	connFile.Close() // child has the fd; parent closes its dup

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

// extractIPFromAddr extracts the bare IP from a net.Addr (strips port).
func extractIPFromAddr(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
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
