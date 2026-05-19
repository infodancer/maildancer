package authoidc

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestStoreContract exercises every Store implementation through the interface
// to confirm they share the same observable behavior. Implementation-specific
// tests (persistence, sweep semantics, driver quirks) live in each impl's own
// test file; this test pins the contract that any future Store backend must
// match.
func TestStoreContract(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T) Store
	}{
		{
			name: "ephemeral",
			make: func(t *testing.T) Store { return newEphemeralStore() },
		},
		{
			name: "sqlite",
			make: func(t *testing.T) Store {
				s, err := newSQLiteStore(filepath.Join(t.TempDir(), "contract.db"), nil)
				if err != nil {
					t.Fatalf("newSQLiteStore: %v", err)
				}
				return s
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.make(t)
			t.Cleanup(func() { _ = s.Close() })

			// Code: store, consume, replay returns ErrNotFound.
			code := &authCode{Code: "ck1", Username: "alice", ExpiresAt: time.Now().Add(time.Minute)}
			s.StoreCode(code)
			got, err := s.ConsumeCode("ck1")
			if err != nil {
				t.Fatalf("ConsumeCode: %v", err)
			}
			if got.Username != "alice" {
				t.Errorf("Username = %q, want alice", got.Username)
			}
			if _, err := s.ConsumeCode("ck1"); !errors.Is(err, ErrNotFound) {
				t.Errorf("replay: got %v, want ErrNotFound", err)
			}

			// Expired code: ConsumeCode returns ErrExpired.
			s.StoreCode(&authCode{Code: "ck2", ExpiresAt: time.Now().Add(-time.Minute)})
			if _, err := s.ConsumeCode("ck2"); !errors.Is(err, ErrExpired) {
				t.Errorf("expired: got %v, want ErrExpired", err)
			}

			// Session: round-trip, expiry, delete.
			sess := &ssoSession{ID: "sk1", Username: "alice", ExpiresAt: time.Now().Add(time.Hour)}
			s.StoreSession(sess)
			if got, ok := s.LookupSession("sk1"); !ok || got.Username != "alice" {
				t.Errorf("LookupSession: %+v ok=%v", got, ok)
			}
			s.DeleteSession("sk1")
			if _, ok := s.LookupSession("sk1"); ok {
				t.Error("session present after DeleteSession")
			}

			// Expired session: LookupSession returns false.
			s.StoreSession(&ssoSession{ID: "sk2", ExpiresAt: time.Now().Add(-time.Second)})
			if _, ok := s.LookupSession("sk2"); ok {
				t.Error("expired session returned as valid")
			}

			// Client: round-trip, scoped by domain.
			c := &registeredClient{
				ClientID:     "dyncli1",
				Domain:       "a.example",
				ClientName:   "app",
				RedirectURIs: []string{"https://a.example/cb"},
				RegisteredAt: time.Now(),
			}
			s.RegisterClient(c)
			if got, ok := s.LookupClient("a.example", "dyncli1"); !ok || got.ClientName != "app" {
				t.Errorf("LookupClient: %+v ok=%v", got, ok)
			}
			// Different domain, same client_id: must not collide.
			if _, ok := s.LookupClient("b.example", "dyncli1"); ok {
				t.Error("LookupClient returned record under wrong domain")
			}

			// SweepExpired clears expired entries.
			s.StoreCode(&authCode{Code: "ck3", ExpiresAt: time.Now().Add(-time.Hour)})
			s.StoreCode(&authCode{Code: "ck4", ExpiresAt: time.Now().Add(time.Hour)})
			if err := s.SweepExpired(time.Now()); err != nil {
				t.Fatalf("SweepExpired: %v", err)
			}
			if _, err := s.ConsumeCode("ck3"); !errors.Is(err, ErrNotFound) {
				t.Errorf("expired code survived sweep: %v", err)
			}
			if _, err := s.ConsumeCode("ck4"); err != nil {
				t.Errorf("fresh code lost to sweep: %v", err)
			}
		})
	}
}
