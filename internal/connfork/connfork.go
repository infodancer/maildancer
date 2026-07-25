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
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ConnFD is the file descriptor number at which the handler subprocess
// inherits the accepted client connection (the first ExtraFiles entry).
const ConnFD = 3

// ReportFD is the file descriptor number at which the handler subprocess
// inherits the write end of the metrics-report pipe (the second ExtraFiles
// entry). Present only when the dispatcher was configured with a ReportSink;
// the child ships its accumulated metrics here just before exiting.
const ReportFD = 4

// Listener is one accept address. Mode is opaque to connfork; it is handed
// back to the Env callback so each daemon defines its own mode vocabulary.
type Listener struct {
	Address string
	Mode    string
}

// Verdict is a PeerGate's answer for one peer.
type Verdict struct {
	// Banned denies the connection.
	Banned bool
	// Tarpit is how long to hold a denied connection open before closing it.
	// Zero closes immediately.
	Tarpit time.Duration
	// Reason is a coarse policy label, for the dispatcher's logs only.
	Reason string
}

// PeerGate decides whether an accepted connection may reach a handler.
//
// Implementations must be safe for concurrent use. A returned error means the
// gate could not reach a verdict; the dispatcher then allows the connection
// (see Config.StrictGate), because a broken gate must not become a total
// outage. Implementations should not apply their own timeout policy -- the
// dispatcher bounds the call with Config.GateTimeout.
type PeerGate interface {
	CheckPeer(ctx context.Context, ip string) (Verdict, error)
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
	// ReportSink, when non-nil, gives each handler the write end of a pipe
	// as ReportFD; the reaper drains the child's report into the sink
	// (reading to EOF, which the child's exit guarantees) before Wait and
	// before OnConnEnd. The pipe is one-way by construction -- the child
	// holds only the write end -- so it can never carry data back into the
	// possibly-lower-privileged child. The sink must tolerate an empty
	// stream (a child that crashed before reporting); its error is logged,
	// not fatal.
	ReportSink func(io.Reader) error
	// MaxConns caps concurrently live handlers. When at the cap the
	// dispatcher stops accepting, so excess connections queue in the
	// kernel backlog rather than being accepted and dropped. 0 = unlimited.
	MaxConns int

	// Gate, when non-nil, is consulted for every accepted connection before
	// a handler is spawned -- so a banned peer costs no subprocess, no TLS
	// handshake, and no password hash. nil allows every connection.
	Gate PeerGate

	// GateTimeout bounds a single Gate call. Default 2s. A timeout is a gate
	// error, handled per StrictGate.
	GateTimeout time.Duration

	// StrictGate makes a gate error deny the connection instead of allowing
	// it. Off by default: failing closed turns an outage in the gate's
	// backing store into a refusal of all mail, which is the outcome an
	// attacker wants. Deployments that would rather be down than unprotected
	// can turn it on.
	StrictGate bool

	// MaxTarpit caps connections held in the tarpit concurrently. Default
	// 256; 0 uses the default, negative disables tarpitting (denied
	// connections close immediately).
	//
	// This budget is deliberately separate from MaxConns. A tarpit that held
	// handler slots would let a spray fill the handler budget with sleeping
	// sockets and starve legitimate clients -- the tarpit would become the
	// vulnerability it exists to mitigate. A tarpitted connection costs one
	// descriptor and one goroutine, with no handler process behind it, so the
	// two budgets can be sized independently.
	MaxTarpit int

	// OnGateVerdict, when non-nil, is called once per gate consultation with
	// "allow", "deny", or "error".
	OnGateVerdict func(verdict string)
	// OnTarpitStart and OnTarpitEnd bracket a tarpitted connection, for a
	// gauge. OnTarpitEnd is guaranteed to follow OnTarpitStart.
	OnTarpitStart func()
	OnTarpitEnd   func()
	// OnTarpitRejected is called when a denied connection is closed
	// immediately because the tarpit budget was full. A nonzero rate means
	// MaxTarpit is undersized.
	OnTarpitRejected func()

	Logger *slog.Logger
}

// Dispatcher-side defaults.
const (
	defaultGateTimeout = 2 * time.Second
	defaultMaxTarpit   = 256
)

// Server accepts connections and spawns one handler subprocess per
// connection.
type Server struct {
	cfg    Config
	wg     sync.WaitGroup
	tokens chan struct{} // nil when unlimited
	// tarpitTokens is the tarpit's own budget, separate from tokens so held
	// connections can never starve handlers. nil when tarpitting is disabled.
	tarpitTokens chan struct{}
}

// NewServer creates a dispatcher from cfg.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.GateTimeout == 0 {
		cfg.GateTimeout = defaultGateTimeout
	}
	s := &Server{cfg: cfg}
	if cfg.MaxConns > 0 {
		s.tokens = make(chan struct{}, cfg.MaxConns)
	}
	switch {
	case cfg.MaxTarpit > 0:
		s.tarpitTokens = make(chan struct{}, cfg.MaxTarpit)
	case cfg.MaxTarpit == 0:
		s.tarpitTokens = make(chan struct{}, defaultMaxTarpit)
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

	s.checkFDHeadroom()

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

// checkFDHeadroom warns at startup when the configured connection and tarpit
// budgets can exceed the process descriptor limit.
//
// Held tarpit connections are descriptors with no handler behind them, so the
// real ceiling on MaxTarpit is RLIMIT_NOFILE -- and discovering that under
// attack, as accept failures, is the worst time to find out.
func (s *Server) checkFDHeadroom() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		s.cfg.Logger.Debug("cannot read RLIMIT_NOFILE", slog.String("error", err.Error()))
		return
	}

	tarpit := 0
	if s.tarpitTokens != nil {
		tarpit = cap(s.tarpitTokens)
	}
	// Each live handler costs the parent a descriptor only transiently, but
	// budget for it anyway; the listeners and the session-manager connection
	// need a handful more.
	const overhead = 32
	needed := uint64(s.cfg.MaxConns + tarpit + overhead)

	if needed > lim.Cur {
		s.cfg.Logger.Warn("connection budgets exceed the descriptor limit",
			slog.Int("max_conns", s.cfg.MaxConns),
			slog.Int("max_tarpit", tarpit),
			slog.Uint64("rlimit_nofile", lim.Cur),
			slog.Uint64("needed", needed))
		return
	}
	s.cfg.Logger.Debug("descriptor headroom",
		slog.Int("max_conns", s.cfg.MaxConns),
		slog.Int("max_tarpit", tarpit),
		slog.Uint64("rlimit_nofile", lim.Cur))
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
		go s.spawnHandler(ctx, conn, lc)
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

// gateVerdict consults the configured gate for clientIP. It reports the
// verdict and whether the connection is denied.
//
// A gate error allows the connection unless StrictGate is set. The error is
// logged at error level and counted, deliberately: a silent fail-open is a
// protection mechanism that can be switched off by breaking the gate's backing
// store, and nobody would notice.
func (s *Server) gateVerdict(ctx context.Context, clientIP string) (Verdict, bool) {
	if s.cfg.Gate == nil || clientIP == "" {
		return Verdict{}, false
	}

	gctx, cancel := context.WithTimeout(ctx, s.cfg.GateTimeout)
	defer cancel()

	verdict, err := s.cfg.Gate.CheckPeer(gctx, clientIP)
	switch {
	case err != nil:
		s.reportVerdict("error")
		s.cfg.Logger.Error("peer gate check failed",
			slog.String("client_ip", clientIP),
			slog.Bool("strict", s.cfg.StrictGate),
			slog.String("error", err.Error()))
		if !s.cfg.StrictGate {
			return Verdict{}, false
		}
		return Verdict{Banned: true, Reason: "gate_error"}, true
	case verdict.Banned:
		s.reportVerdict("deny")
		s.cfg.Logger.Info("connection denied by peer gate",
			slog.String("client_ip", clientIP),
			slog.String("reason", verdict.Reason))
		return verdict, true
	default:
		s.reportVerdict("allow")
		return verdict, false
	}
}

func (s *Server) reportVerdict(verdict string) {
	if s.cfg.OnGateVerdict != nil {
		s.cfg.OnGateVerdict(verdict)
	}
}

// tarpitConn holds a denied connection open for verdict.Tarpit, then closes it
// without sending anything.
//
// Holding costs one descriptor and one goroutine and consumes an attacker
// connection slot for the duration. Nothing is written: a banner or an error
// reply would tell a scanner it reached a live service, whereas a silent hold
// followed by a close is indistinguishable from a blackhole route.
//
// The wait is a blocking read rather than a sleep, so a peer that gives up
// early frees the descriptor immediately. Anything it sends is discarded.
func (s *Server) tarpitConn(ctx context.Context, conn net.Conn, clientIP string, verdict Verdict) {
	if verdict.Tarpit <= 0 || s.tarpitTokens == nil {
		_ = conn.Close()
		return
	}

	// Non-blocking: over the cap, close immediately rather than queueing.
	// Queueing would reintroduce exactly the unbounded hold the separate
	// budget exists to prevent.
	select {
	case s.tarpitTokens <- struct{}{}:
	default:
		if s.cfg.OnTarpitRejected != nil {
			s.cfg.OnTarpitRejected()
		}
		s.cfg.Logger.Warn("tarpit budget full; closing denied connection immediately",
			slog.String("client_ip", clientIP),
			slog.Int("max_tarpit", cap(s.tarpitTokens)))
		_ = conn.Close()
		return
	}

	if s.cfg.OnTarpitStart != nil {
		s.cfg.OnTarpitStart()
	}
	defer func() {
		<-s.tarpitTokens
		if s.cfg.OnTarpitEnd != nil {
			s.cfg.OnTarpitEnd()
		}
		_ = conn.Close()
	}()

	deadline := time.Now().Add(verdict.Tarpit)
	if err := conn.SetReadDeadline(deadline); err != nil {
		// Without a deadline the read below could block indefinitely, so fall
		// back to closing now rather than risk leaking the descriptor.
		return
	}

	// Shutdown must not wait out every held connection.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			return // deadline reached, peer hung up, or shutdown
		}
		if !time.Now().Before(deadline) {
			return
		}
	}
}

// spawnHandler passes conn to a handler subprocess and reaps it
// asynchronously. It owns one limiter token, released when the handler is
// reaped or on any failure to start it.
func (s *Server) spawnHandler(ctx context.Context, conn net.Conn, lc Listener) {
	started := false
	defer func() {
		if !started {
			s.release()
		}
	}()

	clientIP := RemoteIP(conn)

	// Consult the gate before spending anything on this connection. A denial
	// hands the socket to the tarpit, which takes its own budget; the handler
	// token this goroutine holds is returned by the deferred release above.
	//
	// The token is held for the duration of the gate call, so a burst of
	// banned peers can occupy handler slots until their checks resolve. That
	// window is bounded by GateTimeout and is normally a cache hit inside the
	// gate implementation. The alternative -- consulting the gate before
	// acquiring a token -- would mean accepting connections we have no slot
	// for, which is what acquiring before Accept deliberately avoids.
	if verdict, denied := s.gateVerdict(ctx, clientIP); denied {
		go s.tarpitConn(ctx, conn, clientIP, verdict)
		return
	}

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

	// When a report sink is configured, hand the child the write end of a
	// pipe as ReportFD. The child ships its accumulated metrics here just
	// before exiting; the reaper below drains the read end into the sink.
	var reportR *os.File
	if s.cfg.ReportSink != nil {
		r, w, perr := os.Pipe()
		if perr != nil {
			s.cfg.Logger.Error("failed to create report pipe", slog.String("error", perr.Error()))
			// Fall through without the pipe rather than dropping the connection.
		} else {
			reportR = r
			cmd.ExtraFiles = append(cmd.ExtraFiles, w) // becomes ReportFD in the child
			defer func() { _ = w.Close() }()           // parent's copy; closed after Start
		}
	}

	if err := cmd.Start(); err != nil {
		s.cfg.Logger.Error("failed to start handler",
			slog.String("client_ip", clientIP),
			slog.String("error", err.Error()))
		_ = connFile.Close()
		if reportR != nil {
			_ = reportR.Close()
		}
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
		// Drain the child's report before reaping. The parent has already
		// closed its own copy of the write end (deferred above), so this
		// reads to EOF when the child exits and closes ReportFD.
		if reportR != nil {
			if err := s.cfg.ReportSink(reportR); err != nil {
				s.cfg.Logger.Debug("failed to ingest handler report",
					slog.Int("pid", pid),
					slog.String("error", err.Error()))
			}
			_ = reportR.Close()
		}

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

// RemoteIP extracts the bare IP from conn's remote address. Exported because
// the protocol handlers need the peer address in exactly the form the
// dispatcher used -- session-manager keys rate limits and peer bans on it
// (#206), and two implementations of "the peer's address" would eventually
// disagree.
func RemoteIP(conn net.Conn) string {
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

// ChildReportPipe returns the write end of the metrics-report pipe a handler
// subprocess inherited at ReportFD. Call it only when the dispatcher is known
// to have configured a ReportSink (in practice: when metrics are enabled in
// the shared config both processes read) -- the fd number cannot be probed for
// validity, so writes to an unconfigured fd surface as write errors, which the
// caller should log and otherwise ignore.
func ChildReportPipe() *os.File {
	return os.NewFile(uintptr(ReportFD), "report-pipe")
}
