// Package connfork implements the fork-per-connection dispatcher required by
// infodancer/docs/mail-security-model.md: a listener process accepts TCP
// connections and hands each one to a freshly spawned protocol-handler
// subprocess as an inherited file descriptor. The parent never speaks the
// protocol; the child handles exactly one session and exits.
//
// Generalized from smtpd's subprocess server (internal/smtpd/smtp), which
// remains on its own copy until it migrates here after the pattern is proven
// on imapd and pop3d (issue #179).
package connfork

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// ConnFD is the file descriptor number at which the handler subprocess
// inherits the accepted client connection (the first ExtraFiles entry).
// Fd 4 is reserved for a future handler-metrics pipe; do not repurpose it.
const ConnFD = 3

// Listener is one accept address. Mode is opaque to connfork; it is handed
// back to the Env callback so each daemon defines its own mode vocabulary.
type Listener struct {
	Address string
	Mode    string
}

// Config describes how the dispatcher spawns handler subprocesses.
type Config struct {
	// Listeners are the TCP addresses to accept on.
	Listeners []Listener
	// ExecPath is the handler binary (os.Executable() in production).
	ExecPath string
	// Args are the subprocess arguments, e.g.
	// {"protocol-handler", "--config", path}. Static across connections;
	// per-connection metadata travels in the environment.
	Args []string
	// Env builds the child environment from per-connection metadata.
	// nil inherits the parent environment unchanged.
	Env func(clientIP, mode string) []string
	// SysProcAttr is applied to spawned handlers (credential drop).
	// nil spawns with the dispatcher's own credentials.
	SysProcAttr *syscall.SysProcAttr
	// OnConnStart is called after a handler starts; OnConnEnd after it is
	// reaped. Either may be nil. OnConnEnd is guaranteed to follow
	// OnConnStart for the same connection (crash-safe gauge pairing).
	OnConnStart func()
	OnConnEnd   func()
	// MaxConns caps concurrently live handlers. When at the cap the
	// dispatcher stops accepting, so excess connections queue in the
	// kernel backlog rather than being accepted and dropped. 0 = unlimited.
	MaxConns int
	Logger   *slog.Logger
}

// Server accepts connections and spawns one handler subprocess per
// connection.
type Server struct {
	cfg    Config
	wg     sync.WaitGroup
	tokens chan struct{} // nil when unlimited
}

// NewServer creates a dispatcher from cfg.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg}
	if cfg.MaxConns > 0 {
		s.tokens = make(chan struct{}, cfg.MaxConns)
	}
	return s
}

// Run starts accept loops on all configured addresses and blocks until ctx is
// cancelled. Live handler subprocesses are not terminated on shutdown; they
// finish their sessions as orphans.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.ExecPath == "" {
		return errors.New("connfork: ExecPath is required")
	}

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
		s.cfg.Logger.Info("listening (fork-per-connection)",
			slog.String("address", lc.Address),
			slog.String("mode", lc.Mode))
	}

	for i, ln := range lns {
		s.wg.Add(1)
		go func(ln net.Listener, lc Listener) {
			defer s.wg.Done()
			s.acceptLoop(ctx, ln, lc)
		}(ln, s.cfg.Listeners[i])
	}

	<-ctx.Done()
	s.cfg.Logger.Info("shutting down dispatcher")
	for _, ln := range lns {
		_ = ln.Close()
	}
	s.wg.Wait()
	return ctx.Err()
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, lc Listener) {
	for {
		// Acquire a connection slot before accepting, so at the cap new
		// connections wait in the kernel backlog instead of being
		// accepted and then dropped mid-greeting.
		if !s.acquire(ctx) {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			s.release()
			select {
			case <-ctx.Done():
				return
			default:
				s.cfg.Logger.Error("accept error",
					slog.String("address", lc.Address),
					slog.String("error", err.Error()))
				return
			}
		}
		go s.spawnHandler(conn, lc)
	}
}

// acquire blocks until a connection slot is free. It returns false when ctx
// ends first. With no limit configured it returns true immediately.
func (s *Server) acquire(ctx context.Context) bool {
	if s.tokens == nil {
		return true
	}
	select {
	case s.tokens <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) release() {
	if s.tokens != nil {
		<-s.tokens
	}
}

// spawnHandler passes conn to a handler subprocess and reaps it
// asynchronously. It owns one limiter token, released when the handler is
// reaped or on any failure to start it.
func (s *Server) spawnHandler(conn net.Conn, lc Listener) {
	started := false
	defer func() {
		if !started {
			s.release()
		}
	}()

	clientIP := remoteIP(conn)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		s.cfg.Logger.Error("cannot pass non-TCP connection to subprocess",
			slog.String("type", fmt.Sprintf("%T", conn)))
		_ = conn.Close()
		return
	}

	// File() dups the fd so the subprocess can inherit it independently.
	connFile, err := tcpConn.File()
	if err != nil {
		s.cfg.Logger.Error("failed to dup connection fd", slog.String("error", err.Error()))
		_ = conn.Close()
		return
	}

	// Parent relinquishes its copy of the socket; the subprocess owns it.
	_ = conn.Close()

	cmd := exec.Command(s.cfg.ExecPath, s.cfg.Args...)
	cmd.ExtraFiles = []*os.File{connFile} // becomes ConnFD in the child
	if s.cfg.Env != nil {
		cmd.Env = s.cfg.Env(clientIP, lc.Mode)
	}
	cmd.SysProcAttr = s.cfg.SysProcAttr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		s.cfg.Logger.Error("failed to start handler",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		return
	}
	started = true
	_ = connFile.Close() // child has the fd; parent closes its dup

	if s.cfg.OnConnStart != nil {
		s.cfg.OnConnStart()
	}

	pid := cmd.Process.Pid
	s.cfg.Logger.Debug("spawned handler",
		slog.Int("pid", pid),
		slog.String("client_ip", clientIP),
		slog.String("mode", lc.Mode))

	// Reap the subprocess asynchronously to avoid zombies.
	go func() {
		if err := cmd.Wait(); err != nil {
			s.cfg.Logger.Debug("handler exited with error",
				slog.Int("pid", pid),
				slog.String("error", err.Error()))
		} else {
			s.cfg.Logger.Debug("handler exited", slog.Int("pid", pid))
		}
		if s.cfg.OnConnEnd != nil {
			s.cfg.OnConnEnd()
		}
		s.release()
	}()
}

// remoteIP extracts the bare IP from conn's remote address.
func remoteIP(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// ChildConn recovers the accepted client connection in a handler subprocess
// from ConnFD. The inherited file wrapper is closed; the returned net.Conn
// holds its own duplicate.
func ChildConn() (net.Conn, error) {
	f := os.NewFile(uintptr(ConnFD), "client-conn")
	if f == nil {
		return nil, fmt.Errorf("no inherited connection on fd %d", ConnFD)
	}
	defer func() { _ = f.Close() }()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("recover connection from fd %d: %w", ConnFD, err)
	}
	return conn, nil
}
