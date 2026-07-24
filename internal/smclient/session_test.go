package smclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeSM is a controllable in-process session-manager: it can invalidate all
// tokens (simulating the in-memory token map dying with a restart), reject
// logins (password changed), and be stopped/restarted on the same socket
// (simulating the manager being down).
type fakeSM struct {
	smpb.UnimplementedSessionServiceServer
	pb.UnimplementedMailboxServiceServer

	socketPath string

	mu          sync.Mutex
	tokens      map[string]bool
	rejectLogin bool
	loginCount  int
	listCount   int
	setFlags    int
	srv         *grpc.Server
}

func newFakeSM(t *testing.T) *fakeSM {
	t.Helper()
	f := &fakeSM{
		socketPath: filepath.Join(t.TempDir(), "sm.sock"),
		tokens:     make(map[string]bool),
	}
	f.start(t)
	t.Cleanup(f.stop)
	return f
}

// start listens on the fixed socket path, like a restarted session-manager
// re-binding its configured socket.
func (f *fakeSM) start(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("unix", f.socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, f)
	pb.RegisterMailboxServiceServer(srv, f)
	go func() { _ = srv.Serve(ln) }()
	f.mu.Lock()
	f.srv = srv
	f.mu.Unlock()
}

func (f *fakeSM) stop() {
	f.mu.Lock()
	srv := f.srv
	f.srv = nil
	f.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

// invalidateTokens simulates the restart's effect on tokens without a socket
// bounce (covers the Unauthenticated-only path).
func (f *fakeSM) invalidateTokens() {
	f.mu.Lock()
	f.tokens = make(map[string]bool)
	f.mu.Unlock()
}

func (f *fakeSM) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loginCount++
	if f.rejectLogin {
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}
	if req.Username != "alice@test.local" || req.Password != "secret" {
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}
	token := fmt.Sprintf("tok-%d", f.loginCount)
	f.tokens[token] = true
	return &smpb.LoginResponse{SessionToken: token, Mailbox: "alice@test.local"}, nil
}

func (f *fakeSM) Logout(_ context.Context, _ *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	return &smpb.LogoutResponse{}, nil
}

// checkToken mirrors the real proxy: unknown token -> Unauthenticated.
func (f *fakeSM) checkToken(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("session-token")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(vals) == 0 || !f.tokens[vals[0]] {
		return status.Error(codes.Unauthenticated, "unknown session token")
	}
	return nil
}

func (f *fakeSM) List(ctx context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	if err := f.checkToken(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.listCount++
	f.mu.Unlock()
	return &pb.ListResponse{Messages: []*pb.MessageInfo{{Uid: 1, Size: 42}}}, nil
}

func (f *fakeSM) SetFlags(ctx context.Context, _ *pb.SetFlagsRequest) (*pb.SetFlagsResponse, error) {
	if err := f.checkToken(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.setFlags++
	f.mu.Unlock()
	return &pb.SetFlagsResponse{}, nil
}

func (f *fakeSM) UIDValidity(ctx context.Context, _ *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	if err := f.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.UIDValidityResponse{UidValidity: 7, UidNext: 2}, nil
}

func (f *fakeSM) logins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCount
}

func (f *fakeSM) setFlagsCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setFlags
}

// newTestSession logs a session in against the fake and returns it.
func newTestSession(t *testing.T, f *fakeSM, cfg SessionConfig) *Session {
	t.Helper()
	client, err := New(Config{Socket: f.socketPath}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	sess := NewSession(client, cfg, nil)
	if _, err := sess.Login(context.Background(), "alice@test.local", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(sess.Close)
	return sess
}

// TestSession_ReadRecoversAfterTokenInvalidation is the core recovery
// contract: a restarted session-manager invalidates every token; the next
// read re-logs-in with the retained credential and succeeds transparently.
func TestSession_ReadRecoversAfterTokenInvalidation(t *testing.T) {
	f := newFakeSM(t)
	var results []string
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})
	sess.SetRecoveryMetric(func(r string) { results = append(results, r) })

	f.invalidateTokens()

	msgs, err := sess.ListMessages(context.Background(), "INBOX")
	if err != nil {
		t.Fatalf("ListMessages after invalidation: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if got := f.logins(); got != 2 {
		t.Errorf("login count = %d, want 2 (initial + recovery)", got)
	}
	if len(results) != 1 || results[0] != "ok" {
		t.Errorf("recovery metrics = %v, want [ok]", results)
	}
}

// TestSession_ReadRecoversAcrossRestart covers the full down-then-back
// sequence: Unavailable while the socket is gone, then Unauthenticated with
// the stale token, then recovery.
func TestSession_ReadRecoversAcrossRestart(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 10 * time.Second})

	f.stop()

	done := make(chan error, 1)
	go func() {
		_, err := sess.ListMessages(context.Background(), "INBOX")
		done <- err
	}()

	// Let the read hit Unavailable and start backing off, then restart.
	time.Sleep(400 * time.Millisecond)
	f.mu.Lock()
	f.tokens = make(map[string]bool)
	f.mu.Unlock()
	f.start(t)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read did not recover across restart: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("read did not complete after restart")
	}
	if got := f.logins(); got != 2 {
		t.Errorf("login count = %d, want 2", got)
	}
}

// TestSession_WriteIsAtMostOnce: a write that fails on a dead session is not
// replayed -- the server sees at most one SetFlags attempt -- but recovery
// still runs so the next command works.
func TestSession_WriteIsAtMostOnce(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})

	f.invalidateTokens()

	err := sess.SetFlags(context.Background(), "INBOX", 1, []string{"\\Seen"})
	if err == nil {
		t.Fatal("write after invalidation must fail (at-most-once), got nil")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want the original Unauthenticated error surfaced, got %v", err)
	}
	if got := f.setFlagsCalls(); got != 0 {
		t.Errorf("SetFlags executed %d times, want 0 (rejected once, never replayed)", got)
	}

	// Recovery ran: the session is healthy without another login.
	loginsAfterWrite := f.logins()
	if loginsAfterWrite != 2 {
		t.Fatalf("login count after write failure = %d, want 2 (recovery ran)", loginsAfterWrite)
	}
	if _, err := sess.ListMessages(context.Background(), "INBOX"); err != nil {
		t.Fatalf("read after write-failure recovery: %v", err)
	}
	if got := f.logins(); got != loginsAfterWrite {
		t.Errorf("read after recovery triggered another login (%d)", got)
	}
}

// TestSession_CredentialRejectedIsFatal: if re-login is refused (password
// changed), recovery fails permanently and the credential is zeroed.
func TestSession_CredentialRejectedIsFatal(t *testing.T) {
	f := newFakeSM(t)
	var results []string
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})
	sess.SetRecoveryMetric(func(r string) { results = append(results, r) })

	f.invalidateTokens()
	f.mu.Lock()
	f.rejectLogin = true
	f.mu.Unlock()

	_, err := sess.ListMessages(context.Background(), "INBOX")
	if err == nil {
		t.Fatal("want fatal error, got nil")
	}
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("want ErrCredentialRejected, got %v", err)
	}
	if len(results) != 1 || results[0] != "auth_failed" {
		t.Errorf("recovery metrics = %v, want [auth_failed]", results)
	}
	sess.mu.Lock()
	if sess.cred != nil {
		t.Error("credential not zeroed after rejection")
	}
	sess.mu.Unlock()
}

// TestSession_DeadlineExceeded: with the manager staying down, the read gives
// up at the recovery deadline instead of blocking forever.
func TestSession_DeadlineExceeded(t *testing.T) {
	f := newFakeSM(t)
	var results []string
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 700 * time.Millisecond})
	sess.SetRecoveryMetric(func(r string) { results = append(results, r) })

	f.stop()

	start := time.Now()
	_, err := sess.ListMessages(context.Background(), "INBOX")
	if err == nil {
		t.Fatal("want deadline error, got nil")
	}
	if !errors.Is(err, ErrRecoveryDeadline) {
		t.Fatalf("want ErrRecoveryDeadline, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("gave up after %v; deadline was 700ms", elapsed)
	}
	if len(results) != 1 || results[0] != "deadline" {
		t.Errorf("recovery metrics = %v, want [deadline]", results)
	}
}

// TestSession_SingleFlightRecovery: concurrent reads over a dead session
// produce exactly one recovery login.
func TestSession_SingleFlightRecovery(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})

	f.invalidateTokens()

	const n = 8
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := sess.ListMessages(context.Background(), "INBOX"); err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()

	if failures.Load() != 0 {
		t.Errorf("%d concurrent reads failed", failures.Load())
	}
	if got := f.logins(); got != 2 {
		t.Errorf("login count = %d, want 2 (single-flight recovery)", got)
	}
}

// TestSession_RecoveredHookFailureIsFatal: a failed continuity check (e.g.
// UIDVALIDITY changed) aborts recovery.
func TestSession_RecoveredHookFailureIsFatal(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})
	sess.SetRecoveredHook(func(context.Context, *Client, string) error {
		return fmt.Errorf("uidvalidity changed")
	})

	f.invalidateTokens()

	_, err := sess.ListMessages(context.Background(), "INBOX")
	if err == nil || !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("want fatal error from failed continuity check, got %v", err)
	}
}

// TestSession_RecoveredHookRunsWithFreshToken: the hook sees the new token
// and can issue raw-client RPCs.
func TestSession_RecoveredHookRunsWithFreshToken(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{RecoveryDeadline: 5 * time.Second})

	var hookUV uint32
	sess.SetRecoveredHook(func(ctx context.Context, c *Client, token string) error {
		uv, err := c.UIDValidity(ctx, token, "INBOX")
		hookUV = uv
		return err
	})

	f.invalidateTokens()

	if _, err := sess.ListMessages(context.Background(), "INBOX"); err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if hookUV != 7 {
		t.Errorf("hook UIDValidity = %d, want 7", hookUV)
	}
}

// TestSession_CloseZeroesCredential pins the retention hygiene contract.
func TestSession_CloseZeroesCredential(t *testing.T) {
	f := newFakeSM(t)
	sess := newTestSession(t, f, SessionConfig{})

	sess.mu.Lock()
	credBefore := sess.cred
	sess.mu.Unlock()
	if string(credBefore) != "secret" {
		t.Fatalf("credential not retained at login")
	}

	sess.Close()

	for i, b := range credBefore {
		if b != 0 {
			t.Fatalf("credential byte %d not zeroed", i)
		}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.cred != nil || sess.token != "" {
		t.Error("Close did not clear session state")
	}
}
