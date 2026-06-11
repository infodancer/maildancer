package manager

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
)

// mockClients are embedded interface stubs for sessionEntry fields.
type mockMailboxClient struct{ pb.MailboxServiceClient }
type mockFolderClient struct{ pb.FolderServiceClient }
type mockWatchClient struct{ pb.WatchServiceClient }

// newTestManager creates a Manager with auth and spawn hooks for testing.
// Auth always succeeds, returning username as the mailbox.
// Spawn creates a sessionEntry with mock gRPC clients and no real process.
func newTestManager(idleTimeout time.Duration) *Manager {
	m := &Manager{
		cfg:     &config.Config{IdleTimeout: idleTimeout},
		metrics: &metrics.NoopCollector{},
		byToken: make(map[string]*sessionEntry),
		byUser:  make(map[string]*sessionEntry),
	}
	m.authFn = func(_ context.Context, username, _ string) (string, error) {
		return username, nil
	}
	m.spawnFn = func(username, mailbox string) (*sessionEntry, error) {
		return &sessionEntry{
			username:  username,
			mailbox:   mailbox,
			mailboxCl: &mockMailboxClient{},
			folderCl:  &mockFolderClient{},
			watchCl:   &mockWatchClient{},
			refCount:  1,
		}, nil
	}
	return m
}

func TestLogin_NewSession(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	result, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}
	if result.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if result.Mailbox != "alice@example.com" {
		t.Errorf("mailbox = %q, want %q", result.Mailbox, "alice@example.com")
	}

	// Verify internal state.
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byUser["alice@example.com"]
	if !ok {
		t.Fatal("expected entry in byUser")
	}
	if entry.refCount != 1 {
		t.Errorf("refCount = %d, want 1", entry.refCount)
	}
	if _, ok := m.byToken[result.Token]; !ok {
		t.Fatal("expected token in byToken")
	}
}

func TestLogin_ReusesExisting(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	r1, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("first Login() error: %v", err)
	}

	r2, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("second Login() error: %v", err)
	}

	if r1.Token == r2.Token {
		t.Error("expected different tokens for each login")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.byUser["alice@example.com"]
	if entry.refCount != 2 {
		t.Errorf("refCount = %d, want 2", entry.refCount)
	}

	// Both tokens should map to the same entry.
	if m.byToken[r1.Token] != m.byToken[r2.Token] {
		t.Error("expected both tokens to map to the same entry")
	}
}

func TestLogin_AuthFailure(t *testing.T) {
	m := newTestManager(5 * time.Minute)
	m.authFn = func(_ context.Context, _, _ string) (string, error) {
		return "", fmt.Errorf("bad credentials")
	}

	_, err := m.Login(context.Background(), "alice@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error for auth failure")
	}
}

func TestLogin_SpawnFailure(t *testing.T) {
	m := newTestManager(5 * time.Minute)
	m.spawnFn = func(_, _ string) (*sessionEntry, error) {
		return nil, fmt.Errorf("spawn failed")
	}

	_, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err == nil {
		t.Fatal("expected error for spawn failure")
	}
}

func TestLogin_RaceReconciliation(t *testing.T) {
	var spawnCount atomic.Int32
	started := make(chan struct{})

	m := newTestManager(5 * time.Minute)
	m.spawnFn = func(username, mailbox string) (*sessionEntry, error) {
		spawnCount.Add(1)
		// Block until both goroutines have started spawning.
		<-started
		return &sessionEntry{
			username:  username,
			mailbox:   mailbox,
			mailboxCl: &mockMailboxClient{},
			folderCl:  &mockFolderClient{},
			watchCl:   &mockWatchClient{},
			refCount:  1,
		}, nil
	}

	var wg sync.WaitGroup
	var results [2]*LoginResult
	var errs [2]error

	for i := range 2 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = m.Login(context.Background(), "alice@example.com", "pass")
		}(i)
	}

	// Wait for both spawns to start, then unblock them.
	for spawnCount.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	close(started)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Login[%d] error: %v", i, err)
		}
	}

	// Both should succeed with different tokens.
	if results[0].Token == results[1].Token {
		t.Error("expected different tokens")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.byUser["alice@example.com"]
	if entry == nil {
		t.Fatal("expected entry in byUser")
	}
	if entry.refCount != 2 {
		t.Errorf("refCount = %d, want 2", entry.refCount)
	}
}

func TestLogout_RemovesToken(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	result, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if err := m.Logout(context.Background(), result.Token); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.byToken[result.Token]; ok {
		t.Error("expected token to be removed after logout")
	}
}

func TestLogout_StartsIdleTimer(t *testing.T) {
	m := newTestManager(1 * time.Hour) // long timeout so it doesn't fire

	result, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if err := m.Logout(context.Background(), result.Token); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.byUser["alice@example.com"]
	if entry == nil {
		t.Fatal("expected entry still in byUser (timer not fired yet)")
	}
	if entry.idleTimer == nil {
		t.Error("expected idle timer to be set")
	}
	if entry.refCount != 0 {
		t.Errorf("refCount = %d, want 0", entry.refCount)
	}

	// Clean up timer.
	entry.idleTimer.Stop()
}

func TestLogout_UnknownToken(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	err := m.Logout(context.Background(), "nonexistent-token")
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestLogout_MultipleRefs(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	r1, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("first Login() error: %v", err)
	}

	r2, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("second Login() error: %v", err)
	}

	// First logout should not start timer (refCount still > 0).
	if err := m.Logout(context.Background(), r1.Token); err != nil {
		t.Fatalf("Logout(token1) error: %v", err)
	}

	m.mu.Lock()
	entry := m.byUser["alice@example.com"]
	if entry.refCount != 1 {
		t.Errorf("refCount = %d, want 1", entry.refCount)
	}
	if entry.idleTimer != nil {
		t.Error("expected no idle timer while refCount > 0")
	}
	m.mu.Unlock()

	// Second logout should start timer.
	if err := m.Logout(context.Background(), r2.Token); err != nil {
		t.Fatalf("Logout(token2) error: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.idleTimer == nil {
		t.Error("expected idle timer after last logout")
	}
	entry.idleTimer.Stop()
}

func TestReapSession_Idle(t *testing.T) {
	m := newTestManager(20 * time.Millisecond)

	result, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if err := m.Logout(context.Background(), result.Token); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	// Wait for the idle reaper to fire.
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.byUser["alice@example.com"]; ok {
		t.Error("expected entry to be reaped")
	}
	if len(m.byToken) != 0 {
		t.Errorf("expected all tokens to be cleaned up, got %d", len(m.byToken))
	}
}

func TestReapSession_Recovered(t *testing.T) {
	m := newTestManager(50 * time.Millisecond)

	r1, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if err := m.Logout(context.Background(), r1.Token); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	// Login again before the reaper fires.
	r2, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("second Login() error: %v", err)
	}

	// Wait past the original reap timeout.
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byUser["alice@example.com"]
	if !ok {
		t.Fatal("expected entry to survive (refCount recovered)")
	}
	if entry.refCount != 1 {
		t.Errorf("refCount = %d, want 1", entry.refCount)
	}
	if _, ok := m.byToken[r2.Token]; !ok {
		t.Error("expected token2 to still exist")
	}
}

func TestSessionForToken_Valid(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	result, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	mailbox, folders, watch, err := m.SessionForToken(result.Token)
	if err != nil {
		t.Fatalf("SessionForToken() error: %v", err)
	}
	if mailbox == nil || folders == nil || watch == nil {
		t.Error("expected non-nil service clients")
	}
}

func TestSessionForToken_Invalid(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	_, _, _, err := m.SessionForToken("nonexistent")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestClose_TerminatesAll(t *testing.T) {
	m := newTestManager(1 * time.Hour)

	// Create sessions for multiple users.
	for _, user := range []string{"alice@example.com", "bob@example.com"} {
		if _, err := m.Login(context.Background(), user, "pass"); err != nil {
			t.Fatalf("Login(%s) error: %v", user, err)
		}
	}

	m.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.byUser) != 0 {
		t.Errorf("expected byUser to be empty, got %d entries", len(m.byUser))
	}
	if len(m.byToken) != 0 {
		t.Errorf("expected byToken to be empty, got %d entries", len(m.byToken))
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	m := newTestManager(5 * time.Minute)

	entry := &sessionEntry{
		username:  "alice@example.com",
		mailbox:   "alice@example.com",
		mailboxCl: &mockMailboxClient{},
		folderCl:  &mockFolderClient{},
		watchCl:   &mockWatchClient{},
		refCount:  1,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tokens := make(map[string]bool)
	for range 100 {
		token := m.generateTokenLocked(entry)
		if tokens[token] {
			t.Fatalf("duplicate token: %s", token)
		}
		tokens[token] = true
	}
}

func TestLogin_CancelsIdleTimerOnReuse(t *testing.T) {
	m := newTestManager(50 * time.Millisecond)

	r1, err := m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	// Logout to start idle timer.
	if err := m.Logout(context.Background(), r1.Token); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	// Login again before reap -- should cancel the idle timer.
	_, err = m.Login(context.Background(), "alice@example.com", "pass")
	if err != nil {
		t.Fatalf("second Login() error: %v", err)
	}

	m.mu.Lock()
	entry := m.byUser["alice@example.com"]
	if entry.idleTimer != nil {
		t.Error("expected idle timer to be cancelled on reuse")
	}
	if entry.refCount != 1 {
		t.Errorf("refCount = %d, want 1", entry.refCount)
	}
	m.mu.Unlock()

	// Wait past the original timeout -- should NOT be reaped.
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byUser["alice@example.com"]; !ok {
		t.Error("expected entry to survive (timer was cancelled)")
	}
}
