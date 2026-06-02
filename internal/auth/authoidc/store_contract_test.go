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

			// --- signing keys ---

			// Empty domain: ListSigningKeys returns no rows, no error.
			if keys, err := s.ListSigningKeys("k.example"); err != nil || len(keys) != 0 {
				t.Errorf("ListSigningKeys empty: keys=%v err=%v", keys, err)
			}

			// InsertSigningKey: first current key for the domain.
			first := signingKeyRecord{
				Domain: "k.example", KID: "k.example-1", Algorithm: AlgRS256,
				State: keyStateCurrent, CreatedAt: time.Unix(1000, 0),
			}
			if err := s.InsertSigningKey(first); err != nil {
				t.Fatalf("InsertSigningKey: %v", err)
			}
			// Second InsertSigningKey for the same domain must fail (current
			// is unique-per-domain).
			if err := s.InsertSigningKey(signingKeyRecord{
				Domain: "k.example", KID: "k.example-conflict", Algorithm: AlgES256,
				State: keyStateCurrent, CreatedAt: time.Unix(1001, 0),
			}); err == nil {
				t.Error("InsertSigningKey: expected error on second current insert")
			}

			// RotateSigningKey: previous current becomes retiring, new is current.
			second := signingKeyRecord{
				Domain: "k.example", KID: "k.example-1234567890", Algorithm: AlgES256,
				State: keyStateCurrent, CreatedAt: time.Now(),
			}
			if err := s.RotateSigningKey("k.example", second, 24*time.Hour); err != nil {
				t.Fatalf("RotateSigningKey: %v", err)
			}
			keys, err := s.ListSigningKeys("k.example")
			if err != nil {
				t.Fatalf("ListSigningKeys post-rotate: %v", err)
			}
			if len(keys) != 2 {
				t.Fatalf("post-rotate keys: got %d, want 2", len(keys))
			}
			var gotCurrent, gotRetiring int
			for _, k := range keys {
				switch k.State {
				case keyStateCurrent:
					gotCurrent++
					if k.KID != "k.example-1234567890" || k.Algorithm != AlgES256 {
						t.Errorf("current key: kid=%s alg=%s", k.KID, k.Algorithm)
					}
				case keyStateRetiring:
					gotRetiring++
					if k.KID != "k.example-1" {
						t.Errorf("retiring kid: got %s, want k.example-1", k.KID)
					}
					if k.ExpiresAt.IsZero() {
						t.Error("retiring key: ExpiresAt is zero")
					}
				}
			}
			if gotCurrent != 1 || gotRetiring != 1 {
				t.Errorf("state counts: current=%d retiring=%d", gotCurrent, gotRetiring)
			}

			// Domain isolation: another domain's list is unaffected.
			if keys, _ := s.ListSigningKeys("other.example"); len(keys) != 0 {
				t.Errorf("other domain leaked %d keys", len(keys))
			}

			// SweepExpiredSigningKeys: with cutoff in the past, nothing
			// expires; with cutoff far in the future, the retiring key goes.
			swept, err := s.SweepExpiredSigningKeys(time.Now().Add(-time.Hour))
			if err != nil {
				t.Fatalf("SweepExpiredSigningKeys early: %v", err)
			}
			if len(swept) != 0 {
				t.Errorf("early sweep: removed %d keys, want 0", len(swept))
			}
			swept, err = s.SweepExpiredSigningKeys(time.Now().Add(48 * time.Hour))
			if err != nil {
				t.Fatalf("SweepExpiredSigningKeys late: %v", err)
			}
			if len(swept) != 1 || swept[0].KID != "k.example-1" {
				t.Errorf("late sweep: got %+v, want one k.example-1", swept)
			}

			// RevokeSigningKey: marks remaining current as immediately expired.
			if err := s.RevokeSigningKey("k.example", "k.example-1234567890"); err != nil {
				t.Fatalf("RevokeSigningKey: %v", err)
			}
			swept, err = s.SweepExpiredSigningKeys(time.Now())
			if err != nil {
				t.Fatalf("SweepExpiredSigningKeys after revoke: %v", err)
			}
			if len(swept) != 1 {
				t.Errorf("revoke sweep: got %d, want 1", len(swept))
			}
			if err := s.RevokeSigningKey("k.example", "no-such-kid"); err == nil {
				t.Error("RevokeSigningKey: expected error for unknown kid")
			}
		})
	}
}
