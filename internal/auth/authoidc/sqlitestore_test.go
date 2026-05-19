package authoidc

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestSQLiteStore(t *testing.T) (*sqliteStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := newSQLiteStore(path, nil)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestSQLiteStore_CodeRoundTrip(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	c := &authCode{
		Code:        "abc123XYZ_-",
		Domain:      "test.example",
		ClientID:    "client1",
		Username:    "alice",
		RedirectURI: "https://app.example/cb",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	s.StoreCode(c)

	got, err := s.ConsumeCode(c.Code)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.Username != "alice" || got.ClientID != "client1" {
		t.Errorf("ConsumeCode returned wrong record: %+v", got)
	}

	// Replay — second consume must return ErrNotFound.
	if _, err := s.ConsumeCode(c.Code); !errors.Is(err, ErrNotFound) {
		t.Errorf("replay: got %v, want ErrNotFound", err)
	}
}

func TestSQLiteStore_ConsumeCode_Expired(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	c := &authCode{
		Code:      "expiredcode",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	s.StoreCode(c)
	_, err := s.ConsumeCode(c.Code)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expired: got %v, want ErrExpired", err)
	}
	// Even on expiry the row should be removed.
	if _, err := s.ConsumeCode(c.Code); !errors.Is(err, ErrNotFound) {
		t.Errorf("after expired consume: got %v, want ErrNotFound", err)
	}
}

func TestSQLiteStore_ConsumeCode_Concurrent(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	c := &authCode{
		Code:      "concurrent",
		Username:  "bob",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	s.StoreCode(c)

	const N = 32
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		winners  int
		notFound int
	)
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			got, err := s.ConsumeCode(c.Code)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && got != nil:
				winners++
			case errors.Is(err, ErrNotFound):
				notFound++
			default:
				t.Errorf("unexpected: got=%v err=%v", got, err)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Errorf("winners = %d, want 1", winners)
	}
	if notFound != N-1 {
		t.Errorf("notFound = %d, want %d", notFound, N-1)
	}
}

func TestSQLiteStore_SessionRoundTrip(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	sess := &ssoSession{
		ID:        "sess-abc-123",
		Domain:    "test.example",
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s.StoreSession(sess)

	got, ok := s.LookupSession(sess.ID)
	if !ok {
		t.Fatal("LookupSession returned not-found")
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}

	s.DeleteSession(sess.ID)
	if _, ok := s.LookupSession(sess.ID); ok {
		t.Error("session still present after DeleteSession")
	}
}

func TestSQLiteStore_LookupSession_ExpiredEvicts(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	sess := &ssoSession{
		ID:        "expired-session",
		ExpiresAt: time.Now().Add(-time.Second),
	}
	s.StoreSession(sess)

	if _, ok := s.LookupSession(sess.ID); ok {
		t.Error("expired session returned as valid")
	}
	// Subsequent lookup confirms the row is gone (lazy eviction).
	if _, ok := s.LookupSession(sess.ID); ok {
		t.Error("expired session row not evicted")
	}
}

func TestSQLiteStore_ClientRoundTrip(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	c := &registeredClient{
		ClientID:     "dyn_client1",
		Domain:       "test.example",
		ClientName:   "myapp",
		RedirectURIs: []string{"https://app.example/cb", "https://app.example/cb2"},
		RegisteredAt: time.Now(),
	}
	s.RegisterClient(c)

	got, ok := s.LookupClient(c.Domain, c.ClientID)
	if !ok {
		t.Fatal("LookupClient returned not-found")
	}
	if got.ClientName != "myapp" {
		t.Errorf("ClientName = %q, want myapp", got.ClientName)
	}
	if len(got.RedirectURIs) != 2 {
		t.Errorf("RedirectURIs = %v, want 2 entries", got.RedirectURIs)
	}
}

func TestSQLiteStore_LookupClient_DomainScoped(t *testing.T) {
	s, _ := newTestSQLiteStore(t)
	s.RegisterClient(&registeredClient{
		ClientID:     "shared",
		Domain:       "a.example",
		ClientName:   "appA",
		RedirectURIs: []string{"https://a.example/cb"},
		RegisteredAt: time.Now(),
	})
	if _, ok := s.LookupClient("b.example", "shared"); ok {
		t.Error("LookupClient returned record under wrong domain")
	}
	if _, ok := s.LookupClient("a.example", "shared"); !ok {
		t.Error("LookupClient missed record under correct domain")
	}
}

// TestSQLiteStore_ReopenPersists is the durability test required by issue #41:
// state written through one store instance must be readable by a new instance
// pointed at the same database file.
func TestSQLiteStore_ReopenPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	s1, err := newSQLiteStore(path, nil)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}

	client := &registeredClient{
		ClientID:     "dyn_persist",
		Domain:       "test.example",
		ClientName:   "persist",
		RedirectURIs: []string{"https://persist.example/cb"},
		RegisteredAt: time.Now(),
	}
	s1.RegisterClient(client)

	code := &authCode{
		Code:      "persistcode",
		Domain:    "test.example",
		Username:  "alice",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	s1.StoreCode(code)

	sess := &ssoSession{
		ID:        "persistsession",
		Domain:    "test.example",
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s1.StoreSession(sess)

	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}

	// Reopen.
	s2, err := newSQLiteStore(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if got, ok := s2.LookupClient(client.Domain, client.ClientID); !ok {
		t.Error("client lost across reopen")
	} else if got.ClientName != "persist" {
		t.Errorf("client.ClientName = %q, want persist", got.ClientName)
	} else if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://persist.example/cb" {
		t.Errorf("RedirectURIs round-trip mismatch: %v", got.RedirectURIs)
	}

	if got, ok := s2.LookupSession(sess.ID); !ok {
		t.Error("session lost across reopen")
	} else if got.Username != "alice" {
		t.Errorf("session.Username = %q, want alice", got.Username)
	}

	if got, err := s2.ConsumeCode(code.Code); err != nil {
		t.Errorf("code lost across reopen: %v", err)
	} else if got.Username != "alice" {
		t.Errorf("code.Username = %q, want alice", got.Username)
	}
}

func TestSQLiteStore_SweepExpired(t *testing.T) {
	s, _ := newTestSQLiteStore(t)

	s.StoreCode(&authCode{Code: "oldcode", ExpiresAt: time.Now().Add(-time.Hour)})
	s.StoreCode(&authCode{Code: "newcode", ExpiresAt: time.Now().Add(time.Hour)})
	s.StoreSession(&ssoSession{ID: "oldsess", ExpiresAt: time.Now().Add(-time.Hour)})
	s.StoreSession(&ssoSession{ID: "newsess", ExpiresAt: time.Now().Add(time.Hour)})

	if err := s.SweepExpired(time.Now()); err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}

	if _, err := s.ConsumeCode("oldcode"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired code not swept: %v", err)
	}
	if _, err := s.ConsumeCode("newcode"); err != nil {
		t.Errorf("fresh code wrongly swept: %v", err)
	}
	if _, ok := s.LookupSession("oldsess"); ok {
		t.Error("expired session not swept")
	}
	if _, ok := s.LookupSession("newsess"); !ok {
		t.Error("fresh session wrongly swept")
	}
}

func TestSQLiteStore_LookupMissing(t *testing.T) {
	s, _ := newTestSQLiteStore(t)

	if _, err := s.ConsumeCode("doesnotexist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ConsumeCode missing: %v", err)
	}
	if _, ok := s.LookupSession("doesnotexist"); ok {
		t.Error("LookupSession missing returned true")
	}
	if _, ok := s.LookupClient("nodomain.example", "nodyn"); ok {
		t.Error("LookupClient missing returned true")
	}
}

// TestSQLiteStore_OverwriteIsUpsert verifies that StoreSession on an existing
// id replaces the row rather than failing on the primary key.
func TestSQLiteStore_OverwriteIsUpsert(t *testing.T) {
	s, _ := newTestSQLiteStore(t)

	s.StoreSession(&ssoSession{
		ID: "sess1", Domain: "test.example", Username: "first",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	s.StoreSession(&ssoSession{
		ID: "sess1", Domain: "test.example", Username: "second",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	got, ok := s.LookupSession("sess1")
	if !ok {
		t.Fatal("sess1 missing after overwrite")
	}
	if got.Username != "second" {
		t.Errorf("Username = %q, want second", got.Username)
	}
}
