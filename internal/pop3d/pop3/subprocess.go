package pop3

import (
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
//	fd 5  read-only:  protocol-handler reads mail-session responses
//	fd 6  write-only: protocol-handler writes mail-session commands
//
// The dispatcher holds the peer fds: authPipeR, fromSessionW, toSessionR.
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

// spawnHandler pre-allocates three pipe pairs and passes fds 3–6 to a new
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

	// Pre-allocate all three pipe pairs before forking.
	//
	//  authPipeR  (dispatcher reads)   ←  authPipeW  (child fd 4, writes signal)
	//  fromSessR  (child fd 5, reads)  ←  fromSessW  (mail-session stdout)
	//  toSessR    (mail-session stdin) ←  toSessW    (child fd 6, writes cmds)
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
	toSessR, toSessW, err := os.Pipe()
	if err != nil {
		s.logger.Error("failed to create toSession pipe",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		_ = authPipeR.Close()
		_ = authPipeW.Close()
		_ = fromSessR.Close()
		_ = fromSessW.Close()
		return
	}

	cmd := exec.Command(s.execPath, "protocol-handler", "--config", s.configPath)
	cmd.ExtraFiles = []*os.File{
		connFile,  // fd 3 — TCP socket
		authPipeW, // fd 4 — write auth signal to dispatcher
		fromSessR, // fd 5 — read responses from mail-session
		toSessW,   // fd 6 — write commands to mail-session
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
		_ = toSessR.Close()
		_ = toSessW.Close()
		return
	}

	// Close fds that now belong to the child — parent keeps only the peer ends.
	_ = connFile.Close()
	_ = authPipeW.Close()
	_ = fromSessR.Close()
	_ = toSessW.Close()

	pid := cmd.Process.Pid
	s.logger.Debug("spawned protocol-handler",
		slog.Int("pid", pid),
		slog.String("client_ip", clientIP),
		slog.String("mode", string(lc.Mode)))

	// Dispatcher goroutine: wait for auth signal, fork mail-session, reap both.
	go s.dispatchSession(cmd, authPipeR, toSessR, fromSessW, clientIP)
}

// dispatchSession reads the auth signal from authPipeR, looks up credentials,
// forks mail-session, then reaps both subprocesses.
func (s *SubprocessServer) dispatchSession(
	phCmd *exec.Cmd,
	authPipeR, toSessR, fromSessW *os.File,
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
		_ = toSessR.Close()
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
		_ = toSessR.Close()
		_ = fromSessW.Close()
		return
	}

	uid, gid, basePath, err := s.lookupCredentials(sig.Username)
	if err != nil {
		s.logger.Error("credential lookup failed",
			slog.String("client_ip", clientIP),
			slog.String("username", sig.Username),
			slog.String("error", err.Error()))
		_ = toSessR.Close()
		_ = fromSessW.Close()
		return
	}

	msCmd := exec.Command(s.mailSessionPath, "--type", "maildir", "--basepath", basePath)
	msCmd.Stdin = toSessR
	msCmd.Stdout = fromSessW
	msCmd.Stderr = os.Stderr
	msCmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}

	if err := msCmd.Start(); err != nil {
		s.logger.Error("failed to start mail-session",
			slog.String("client_ip", clientIP),
			slog.String("username", sig.Username),
			slog.String("error", err.Error()))
		_ = toSessR.Close()
		_ = fromSessW.Close()
		return
	}

	// Parent closes its copies; the child processes own these fds now.
	_ = toSessR.Close()
	_ = fromSessW.Close()

	s.logger.Debug("spawned mail-session",
		slog.Int("pid", msCmd.Process.Pid),
		slog.String("client_ip", clientIP),
		slog.String("username", sig.Username),
		slog.Uint64("uid", uint64(uid)),
		slog.Uint64("gid", uint64(gid)))

	// Reap mail-session asynchronously; it exits when the session pipe closes.
	go func() {
		if err := msCmd.Wait(); err != nil {
			s.logger.Debug("mail-session exited",
				slog.Int("pid", msCmd.Process.Pid),
				slog.String("error", err.Error()))
		} else {
			s.logger.Debug("mail-session exited",
				slog.Int("pid", msCmd.Process.Pid))
		}
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
