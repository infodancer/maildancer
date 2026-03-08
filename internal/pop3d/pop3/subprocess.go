package pop3

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// SubprocessServer accepts TCP connections on configured addresses and spawns a
// protocol-handler subprocess for each one. After the protocol-handler
// authenticates the user it writes an auth signal to the auth pipe; the
// dispatcher goroutine then forks mail-session with the appropriate uid/gid.
//
// fd layout in the protocol-handler child:
//
//	fd 3  TCP socket (from listener)
//	fd 4  write-only: protocol-handler writes auth signal to dispatcher
//	fd 5  read-only:  protocol-handler reads gRPC socket path from dispatcher
type SubprocessServer struct {
	listeners       []config.ListenerConfig
	execPath        string
	configPath      string
	domainsPath     string // directory containing per-domain subdirectories
	mailSessionPath string // path to the mail-session binary; empty = disabled
	logger          *slog.Logger
	wg              sync.WaitGroup
}

// NewSubprocessServer creates a SubprocessServer.
// execPath is the path to the pop3d binary (use os.Executable()).
// configPath is passed to each protocol-handler subprocess via --config.
// domainsPath is the directory containing per-domain subdirectories; used to
// look up uid/gid after an auth signal is received. Empty disables domain
// credential lookup.
// mailSessionPath is the path to the mail-session binary. Empty disables
// mail-session spawning.
func NewSubprocessServer(
	listeners []config.ListenerConfig,
	execPath, configPath, domainsPath, mailSessionPath string,
	logger *slog.Logger,
) *SubprocessServer {
	return &SubprocessServer{
		listeners:       listeners,
		execPath:        execPath,
		configPath:      configPath,
		domainsPath:     domainsPath,
		mailSessionPath: mailSessionPath,
		logger:          logger,
	}
}

// Run starts accept loops on all configured ports and blocks until ctx is cancelled.
func (s *SubprocessServer) Run(ctx context.Context) error {
	lns := make([]net.Listener, 0, len(s.listeners))
	for _, lc := range s.listeners {
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
		}(ln, s.listeners[i])
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

// spawnHandler pre-allocates two pipe pairs and passes fds 3–5 to a new
// protocol-handler subprocess, then starts a dispatcher goroutine.
func (s *SubprocessServer) spawnHandler(conn net.Conn, lc config.ListenerConfig) {
	clientIP := extractIPFromAddr(conn.RemoteAddr())

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
		s.logger.Error("failed to dup connection fd",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = conn.Close()
		return
	}
	// Parent relinquishes its copy of the socket; subprocess owns it.
	_ = conn.Close()

	// Pre-allocate pipe pairs before forking.
	//
	//  authPipeR  (dispatcher reads)   ←  authPipeW  (child fd 4, writes signal)
	//  fromSessR  (child fd 5, reads)  ←  fromSessW  (dispatcher writes socket path)
	authPipeR, authPipeW, err := os.Pipe()
	if err != nil {
		s.logger.Error("failed to create auth pipe",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		return
	}
	fromSessR, fromSessW, err := os.Pipe()
	if err != nil {
		s.logger.Error("failed to create fromSession pipe",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		_ = authPipeR.Close()
		_ = authPipeW.Close()
		return
	}

	cmd := exec.Command(s.execPath, "protocol-handler", "--config", s.configPath)
	cmd.ExtraFiles = []*os.File{
		connFile,  // fd 3 — TCP socket
		authPipeW, // fd 4 — write auth signal to dispatcher
		fromSessR, // fd 5 — read gRPC socket path from dispatcher
	}
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
		_ = connFile.Close()
		_ = authPipeR.Close()
		_ = authPipeW.Close()
		_ = fromSessR.Close()
		_ = fromSessW.Close()
		return
	}

	// Close fds that now belong to the child — parent keeps only the peer ends.
	_ = connFile.Close()
	_ = authPipeW.Close()
	_ = fromSessR.Close()

	pid := cmd.Process.Pid
	s.logger.Debug("spawned protocol-handler",
		slog.Int("pid", pid),
		slog.String("client_ip", clientIP),
		slog.String("mode", string(lc.Mode)))

	// Dispatcher goroutine: wait for auth signal, fork mail-session, reap both.
	go s.dispatchSession(cmd, fromSessW, authPipeR, clientIP)
}

// dispatchSession reads the auth signal from authPipeR, looks up credentials,
// spawns mail-session in gRPC daemon mode, then reaps both subprocesses.
func (s *SubprocessServer) dispatchSession(
	phCmd *exec.Cmd,
	fromSessW, authPipeR *os.File,
	clientIP string,
) {
	defer func() {
		if err := phCmd.Wait(); err != nil {
			s.logger.Debug("protocol-handler exited",
				slog.Int("pid", phCmd.Process.Pid),
				slog.String("client_ip", clientIP),
				slog.String("error", err.Error()))
		} else {
			s.logger.Debug("protocol-handler exited",
				slog.Int("pid", phCmd.Process.Pid),
				slog.String("client_ip", clientIP))
		}
	}()

	// Read the auth signal. When the protocol-handler exits without
	// authenticating (wrong password, timeout, etc.) authPipeR returns EOF.
	sig, err := readAuthSignal(authPipeR)
	_ = authPipeR.Close()
	if err != nil {
		s.logger.Debug("no auth signal received",
			slog.String("client_ip", clientIP),
			slog.String("reason", err.Error()))
		_ = fromSessW.Close()
		return
	}

	s.logger.Debug("received auth signal",
		slog.String("client_ip", clientIP),
		slog.String("username", sig.Username))

	// If mail-session is not configured, release the pipes and return. The
	// protocol-handler accesses the mailbox directly (pre-#20 behaviour).
	if s.mailSessionPath == "" || s.domainsPath == "" {
		s.logger.Debug("mail-session not configured, skipping spawn",
			slog.String("client_ip", clientIP))
		_ = fromSessW.Close()
		return
	}

	uid, gid, basePath, err := s.lookupCredentials(sig.Username)
	if err != nil {
		s.logger.Error("credential lookup failed",
			slog.String("client_ip", clientIP),
			slog.String("username", sig.Username),
			slog.String("error", err.Error()))
		_ = fromSessW.Close()
		return
	}

	s.dispatchGrpcSession(phCmd, fromSessW, sig.Username, uid, gid, basePath, clientIP)
}

// dispatchGrpcSession spawns mail-session in gRPC daemon mode and writes the
// socket path to fromSessW so the protocol-handler can dial gRPC.
func (s *SubprocessServer) dispatchGrpcSession(
	phCmd *exec.Cmd,
	fromSessW *os.File,
	username string, uid, gid uint32, basePath, clientIP string,
) {
	// Create a temp directory for the unix socket.
	tmpDir, err := os.MkdirTemp("", "mail-session-*")
	if err != nil {
		s.logger.Error("failed to create temp dir for gRPC socket",
			slog.String("client_ip", clientIP),
			slog.String("username", username),
			slog.String("error", err.Error()))
		_ = fromSessW.Close()
		return
	}

	socketPath := filepath.Join(tmpDir, "session.sock")

	msCmd := exec.Command(s.mailSessionPath,
		"--mode=daemon",
		"--socket="+socketPath,
		"--mailbox="+username,
		"--type=maildir",
		"--basepath="+basePath,
	)
	msCmd.Stderr = os.Stderr
	msCmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}

	// Capture stdout for READY signal.
	stdout, err := msCmd.StdoutPipe()
	if err != nil {
		s.logger.Error("failed to create stdout pipe for mail-session",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = fromSessW.Close()
		_ = os.RemoveAll(tmpDir)
		return
	}

	if err := msCmd.Start(); err != nil {
		s.logger.Error("failed to start mail-session (grpc)",
			slog.String("client_ip", clientIP),
			slog.String("username", username),
			slog.String("error", err.Error()))
		_ = fromSessW.Close()
		_ = os.RemoveAll(tmpDir)
		return
	}

	s.logger.Debug("spawned mail-session (grpc)",
		slog.Int("pid", msCmd.Process.Pid),
		slog.String("client_ip", clientIP),
		slog.String("username", username),
		slog.String("socket", socketPath),
		slog.Uint64("uid", uint64(uid)),
		slog.Uint64("gid", uint64(gid)))

	// Wait for READY signal from mail-session.
	readyCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				readyCh <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			readyCh <- fmt.Errorf("reading stdout: %w", err)
		} else {
			readyCh <- fmt.Errorf("mail-session exited without READY signal")
		}
	}()

	err = <-readyCh
	if err != nil {
		s.logger.Error("mail-session gRPC not ready",
			slog.String("client_ip", clientIP),
			slog.String("username", username),
			slog.String("error", err.Error()))
		_ = msCmd.Process.Kill()
		_ = msCmd.Wait()
		_ = fromSessW.Close()
		_ = os.RemoveAll(tmpDir)
		return
	}

	// Write socket path to fromSessW so the protocol-handler can read it from fd 5.
	if _, err := fmt.Fprintf(fromSessW, "%s\n", socketPath); err != nil {
		s.logger.Error("failed to write socket path to protocol-handler",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = msCmd.Process.Kill()
		_ = msCmd.Wait()
		_ = fromSessW.Close()
		_ = os.RemoveAll(tmpDir)
		return
	}
	_ = fromSessW.Close()

	// Reap mail-session when the protocol-handler exits.
	go func() {
		// Wait for protocol-handler to exit first.
		_ = phCmd.Wait()
		// Then stop mail-session gracefully.
		_ = msCmd.Process.Signal(syscall.SIGTERM)
		if err := msCmd.Wait(); err != nil {
			s.logger.Debug("mail-session exited",
				slog.Int("pid", msCmd.Process.Pid),
				slog.String("error", err.Error()))
		} else {
			s.logger.Debug("mail-session exited",
				slog.Int("pid", msCmd.Process.Pid))
		}
		_ = os.RemoveAll(tmpDir)
	}()
}

// lookupCredentials resolves uid, gid, and mail-session basePath for a
// fully-qualified username (localpart@domain). It reads the per-domain config
// and passwd file from the domains directory.
func (s *SubprocessServer) lookupCredentials(username string) (uid, gid uint32, basePath string, err error) {
	localpart, domainName, ok := strings.Cut(username, "@")
	if !ok {
		return 0, 0, "", fmt.Errorf("invalid username %q: missing @domain", username)
	}

	domainDir := filepath.Join(s.domainsPath, domainName)

	// Load per-domain config; treat a missing file as an empty config.
	cfg, cfgErr := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if cfgErr != nil {
		cfg = &domain.DomainConfig{}
	}

	gid = cfg.Gid

	// Resolve credential backend path (default: "passwd").
	credBackend := cfg.Auth.CredentialBackend
	if credBackend == "" {
		credBackend = "passwd"
	}
	passwdPath := credBackend
	if !filepath.IsAbs(passwdPath) {
		passwdPath = filepath.Join(domainDir, passwdPath)
	}

	uid, err = passwd.LookupUID(passwdPath, localpart)
	if err != nil {
		return 0, 0, "", fmt.Errorf("lookup uid for %q in %q: %w", localpart, passwdPath, err)
	}

	// Resolve mail-session basePath (default: "users").
	base := cfg.MsgStore.BasePath
	if base == "" {
		base = "users"
	}
	if !filepath.IsAbs(base) {
		base = filepath.Join(domainDir, base)
	}

	return uid, gid, base, nil
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
