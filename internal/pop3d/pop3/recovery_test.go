package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/logging"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// recoverySM is a token-aware mock session-manager: emptying its token map
// simulates a session-manager restart; stopping the server simulates it
// being down.
type recoverySM struct {
	smpb.UnimplementedSessionServiceServer
	pb.UnimplementedMailboxServiceServer

	socketPath string

	mu      sync.Mutex
	tokens  map[string]bool
	logins  int
	deletes int
	down    bool
	srv     *grpc.Server
}

func startRecoverySM(t *testing.T) *recoverySM {
	t.Helper()
	m := &recoverySM{
		socketPath: filepath.Join(t.TempDir(), "sm.sock"),
		tokens:     make(map[string]bool),
	}
	ln, err := net.Listen("unix", m.socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, m)
	pb.RegisterMailboxServiceServer(srv, m)
	go func() { _ = srv.Serve(ln) }()
	m.srv = srv
	t.Cleanup(srv.Stop)
	return m
}

func (m *recoverySM) invalidateTokens() {
	m.mu.Lock()
	m.tokens = make(map[string]bool)
	m.mu.Unlock()
}

// goDown makes every RPC fail as if the manager process were gone.
func (m *recoverySM) goDown() {
	m.mu.Lock()
	m.down = true
	m.mu.Unlock()
}

func (m *recoverySM) check(ctx context.Context) error {
	m.mu.Lock()
	down := m.down
	m.mu.Unlock()
	if down {
		return status.Error(codes.Unavailable, "session-manager down")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("session-token")
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(vals) == 0 || !m.tokens[vals[0]] {
		return status.Error(codes.Unauthenticated, "unknown session token")
	}
	return nil
}

func (m *recoverySM) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, status.Error(codes.Unavailable, "session-manager down")
	}
	if req.Username != "alice@test.local" || req.Password != "testpass" {
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}
	m.logins++
	token := fmt.Sprintf("tok-%d", m.logins)
	m.tokens[token] = true
	return &smpb.LoginResponse{SessionToken: token, Mailbox: "alice@test.local"}, nil
}

func (m *recoverySM) Logout(_ context.Context, _ *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	return &smpb.LogoutResponse{}, nil
}

func (m *recoverySM) List(ctx context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	return &pb.ListResponse{Messages: []*pb.MessageInfo{{Uid: 1, Size: 20}}}, nil
}

func (m *recoverySM) Stat(ctx context.Context, _ *pb.StatRequest) (*pb.StatResponse, error) {
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	return &pb.StatResponse{Count: 1, TotalBytes: 20}, nil
}

func (m *recoverySM) Fetch(req *pb.FetchRequest, stream grpc.ServerStreamingServer[pb.FetchResponse]) error {
	if err := m.check(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&pb.FetchResponse{Data: []byte("Subject: hi\r\n\r\nbody\r\n")})
}

func (m *recoverySM) Delete(ctx context.Context, _ *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.deletes++
	m.mu.Unlock()
	return &pb.DeleteResponse{}, nil
}

func (m *recoverySM) Expunge(ctx context.Context, _ *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	return &pb.ExpungeResponse{}, nil
}

func (m *recoverySM) loginCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logins
}

// pop3RecoveryClient runs a scripted POP3 conversation over a live stack.
type pop3RecoveryClient struct {
	conn net.Conn
	r    *bufio.Reader
	t    *testing.T
}

func startPop3RecoveryEnv(t *testing.T, deadline string) (*recoverySM, *pop3RecoveryClient) {
	t.Helper()
	sm := startRecoverySM(t)

	cfg := config.Default()
	cfg.Hostname = "recovery.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sm.socketPath}
	cfg.Listeners = nil
	cfg.Timeouts.SessionRecoveryDeadline = deadline

	stack, err := pop3.NewStack(pop3.StackConfig{
		Config:    cfg,
		Collector: &metrics.NoopCollector{},
		Logger:    logging.NewLogger("error"),
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = stack.RunSingleConn(c, config.ModePop3) }()
		}
	}()

	conn, err := net.DialTimeout("tcp", tcpLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	c := &pop3RecoveryClient{conn: conn, r: bufio.NewReader(conn), t: t}
	if g := c.readLine(); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.expectOK("USER alice@test.local")
	c.expectOK("PASS testpass")
	return sm, c
}

func (c *pop3RecoveryClient) readLine() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *pop3RecoveryClient) send(cmd string) string {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.conn, "%s\r\n", cmd); err != nil {
		c.t.Fatalf("write %s: %v", cmd, err)
	}
	return c.readLine()
}

func (c *pop3RecoveryClient) expectOK(cmd string) string {
	c.t.Helper()
	resp := c.send(cmd)
	if !strings.HasPrefix(resp, "+OK") {
		c.t.Fatalf("%s = %q, want +OK", cmd, resp)
	}
	return resp
}

// drainMultiline consumes a multi-line response up to the terminating dot.
func (c *pop3RecoveryClient) drainMultiline() {
	c.t.Helper()
	for {
		if c.readLine() == "." {
			return
		}
	}
}

// TestPop3_TransparentRecoveryAcrossRestart: after the session-manager
// "restarts" (tokens invalidated), the next RETR succeeds without the POP3
// client re-authenticating.
func TestPop3_TransparentRecoveryAcrossRestart(t *testing.T) {
	sm, c := startPop3RecoveryEnv(t, "5s")

	sm.invalidateTokens()

	resp := c.send("RETR 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("RETR after restart = %q, want +OK (transparent recovery)", resp)
	}
	c.drainMultiline()
	if got := sm.loginCount(); got != 2 {
		t.Errorf("login count = %d, want 2 (transparent re-login)", got)
	}
}

// TestPop3_QuitCommitFailureIsERR: RFC 1939 ordering -- the UPDATE-state
// commit runs before the QUIT response, and a commit that cannot complete
// (manager down past the recovery deadline) answers -ERR so the client knows
// its deletions were not applied. Previously +OK was sent first and commit
// errors were silently swallowed.
func TestPop3_QuitCommitFailureIsERR(t *testing.T) {
	sm, c := startPop3RecoveryEnv(t, "600ms")

	c.expectOK("DELE 1")
	sm.goDown()

	resp := c.send("QUIT")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("QUIT with dead session-manager = %q, want -ERR", resp)
	}
}

// TestPop3_QuitCommitSucceedsAfterRecovery: a commit that hits the restart
// window recovers and applies the deletion, answering +OK.
func TestPop3_QuitCommitSucceedsAfterRecovery(t *testing.T) {
	sm, c := startPop3RecoveryEnv(t, "5s")

	c.expectOK("DELE 1")
	sm.invalidateTokens()

	resp := c.send("QUIT")
	if !strings.HasPrefix(resp, "-ERR") {
		// The Delete write itself is at-most-once: the failed attempt is
		// not replayed, so the commit reports failure even though the
		// session recovered. This pins the at-most-once contract.
		t.Fatalf("QUIT commit across restart = %q, want -ERR (write not replayed)", resp)
	}
	if got := sm.loginCount(); got != 2 {
		t.Errorf("login count = %d, want 2 (recovery ran for the commit)", got)
	}
}
