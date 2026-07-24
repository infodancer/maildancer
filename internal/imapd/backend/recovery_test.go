package backend_test

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

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
)

// recoverySM is a token-aware mock session-manager: invalidating its token
// map simulates the effect of a session-manager restart (the real token maps
// are in-memory and die with the process).
type recoverySM struct {
	smpb.UnimplementedSessionServiceServer
	pb.UnimplementedMailboxServiceServer
	pb.UnimplementedFolderServiceServer

	mu          sync.Mutex
	tokens      map[string]bool
	logins      int
	uidValidity uint32
}

func (m *recoverySM) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *recoverySM) checkToken(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("session-token")
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(vals) == 0 || !m.tokens[vals[0]] {
		return status.Error(codes.Unauthenticated, "unknown session token")
	}
	return nil
}

func (m *recoverySM) invalidateTokens() {
	m.mu.Lock()
	m.tokens = make(map[string]bool)
	m.mu.Unlock()
}

func (m *recoverySM) loginCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logins
}

func (m *recoverySM) setUIDValidity(v uint32) {
	m.mu.Lock()
	m.uidValidity = v
	m.mu.Unlock()
}

func (m *recoverySM) List(ctx context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	if err := m.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.ListResponse{Messages: []*pb.MessageInfo{{Uid: 1, Size: 100}}}, nil
}

func (m *recoverySM) Stat(ctx context.Context, _ *pb.StatRequest) (*pb.StatResponse, error) {
	if err := m.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.StatResponse{Count: 1, TotalBytes: 100}, nil
}

func (m *recoverySM) UIDValidity(ctx context.Context, _ *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	if err := m.checkToken(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	uv := m.uidValidity
	m.mu.Unlock()
	return &pb.UIDValidityResponse{UidValidity: uv, UidNext: 2}, nil
}

func (m *recoverySM) ListFolders(ctx context.Context, _ *pb.ListFoldersRequest) (*pb.ListFoldersResponse, error) {
	if err := m.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.ListFoldersResponse{Folders: []string{"INBOX"}}, nil
}

func (m *recoverySM) CreateFolder(ctx context.Context, _ *pb.CreateFolderRequest) (*pb.CreateFolderResponse, error) {
	if err := m.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.CreateFolderResponse{}, nil
}

// startRecoveryEnv boots the mock session-manager and an imapd stack serving
// individual connections, and returns a logged-in, SELECTed IMAP client
// conversation helper.
func startRecoveryEnv(t *testing.T) (*recoverySM, func(tag, cmd string) []string) {
	t.Helper()

	sm := &recoverySM{tokens: make(map[string]bool), uidValidity: 42}
	sock := filepath.Join(t.TempDir(), "sm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, sm)
	pb.RegisterMailboxServiceServer(srv, sm)
	pb.RegisterFolderServiceServer(srv, sm)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	cfg := config.Default()
	cfg.Hostname = "recovery.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = nil
	cfg.Timeouts.SessionRecoveryDeadline = "5s"

	stack, err := backend.NewStack(backend.StackConfig{Config: cfg})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = stack.ServeConn(c, config.ModeImap) }()
		}
	}()

	conn, err := net.DialTimeout("tcp", tcpLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting: %v", err)
	}

	sendCmd := func(tag, cmd string) []string {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %s: %v", tag, err)
		}
		var lines []string
		for {
			line, rerr := r.ReadString('\n')
			if rerr != nil {
				t.Fatalf("read response for %s: %v", tag, rerr)
			}
			line = strings.TrimRight(line, "\r\n")
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				return lines
			}
		}
	}

	if resp := sendCmd("A1", "LOGIN alice@test.local testpass"); !strings.HasPrefix(resp[len(resp)-1], "A1 OK") {
		t.Fatalf("LOGIN failed: %s", resp[len(resp)-1])
	}
	if resp := sendCmd("A2", "SELECT INBOX"); !strings.HasPrefix(resp[len(resp)-1], "A2 OK") {
		t.Fatalf("SELECT failed: %s", resp[len(resp)-1])
	}
	return sm, sendCmd
}

// TestSession_TransparentRecoveryAcrossRestart is the imapd-level acceptance
// test for session-recovery-design.md: after the session-manager "restarts"
// (all tokens invalidated), the next client command succeeds without the
// IMAP client reconnecting or re-authenticating -- the handler re-logs-in
// with its retained credential and the UIDVALIDITY continuity check passes.
func TestSession_TransparentRecoveryAcrossRestart(t *testing.T) {
	sm, sendCmd := startRecoveryEnv(t)

	if got := sm.loginCount(); got != 1 {
		t.Fatalf("login count before restart = %d, want 1", got)
	}

	sm.invalidateTokens()

	resp := sendCmd("A3", "SELECT INBOX")
	if !strings.HasPrefix(resp[len(resp)-1], "A3 OK") {
		t.Fatalf("SELECT after restart failed (recovery did not happen): %v", resp)
	}
	if got := sm.loginCount(); got != 2 {
		t.Errorf("login count after recovery = %d, want 2 (transparent re-login)", got)
	}
}

// TestSession_UIDValidityChangeAbortsRecovery: when the selected folder's
// UIDVALIDITY changed across the restart, transparent resumption of the
// in-progress session would violate IMAP semantics (the client's cached UIDs
// are stale and it has not been told). A mid-session operation that does not
// re-report UIDVALIDITY must therefore fail rather than silently resume.
//
// Note a fresh SELECT is deliberately NOT guarded: go-imap unselects first
// (hook sees no selected folder) and the SELECT response itself carries the
// new UIDVALIDITY, which is exactly how IMAP tells a client to resync.
func TestSession_UIDValidityChangeAbortsRecovery(t *testing.T) {
	sm, sendCmd := startRecoveryEnv(t)

	sm.invalidateTokens()
	sm.setUIDValidity(43) // mailbox recreated while we were away

	resp := sendCmd("A3", "STATUS INBOX (MESSAGES)")
	if !strings.HasPrefix(resp[len(resp)-1], "A3 NO") {
		t.Fatalf("STATUS after UIDVALIDITY change = %v, want tagged NO", resp)
	}
}
