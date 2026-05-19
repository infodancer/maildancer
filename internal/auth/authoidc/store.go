package authoidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrNotFound is returned when a code or session does not exist.
var ErrNotFound = errors.New("not found")

// ErrExpired is returned when a code or session has expired.
var ErrExpired = errors.New("expired")

// authCode holds a pending authorization code awaiting exchange.
type authCode struct {
	Code          string
	Domain        string
	ClientID      string
	Username      string
	RedirectURI   string
	PKCEChallenge string
	PKCEMethod    string
	Nonce         string
	ExpiresAt     time.Time
}

// ssoSession holds an active browser SSO session for a user.
type ssoSession struct {
	ID        string
	Domain    string
	Username  string
	ExpiresAt time.Time
}

// registeredClient holds metadata for a dynamically registered OIDC client (RFC 7591).
// Dynamic clients are always public (PKCE-only; no client secret).
type registeredClient struct {
	ClientID     string
	Domain       string
	ClientName   string
	RedirectURIs []string
	RegisteredAt time.Time
}

// Store is the persistence contract for OIDC authorization codes, SSO sessions,
// and dynamically registered clients. Implementations must keep ConsumeCode
// atomic — a single caller succeeds even under concurrent attempts.
//
// StoreCode, StoreSession, and RegisterClient return no error; backends should
// log failures rather than propagate them, since the user-visible outcome of a
// dropped write (invalid_grant at token exchange, fresh login on next request)
// is equivalent to the entry never having existed.
type Store interface {
	StoreCode(c *authCode)
	ConsumeCode(code string) (*authCode, error)

	StoreSession(sess *ssoSession)
	LookupSession(id string) (*ssoSession, bool)
	DeleteSession(id string)

	RegisterClient(c *registeredClient)
	LookupClient(domain, clientID string) (*registeredClient, bool)

	// SweepExpired removes codes and sessions whose ExpiresAt is at or before
	// now. Clients are never swept (they have no expiry). Implementations may
	// return errors from underlying I/O for logging purposes.
	SweepExpired(now time.Time) error

	// Close releases any resources held by the store (open file handles,
	// background goroutines). Idempotent.
	Close() error
}

// ephemeralStore is an in-memory store for auth codes, SSO sessions, and
// registered clients. State is lost on process restart — use only in tests or
// for deployments that explicitly do not require durability.
type ephemeralStore struct {
	mu       sync.Mutex
	codes    map[string]*authCode
	sessions map[string]*ssoSession
	clients  map[string]*registeredClient // key: "domain\x00clientID"
}

func newEphemeralStore() *ephemeralStore {
	return &ephemeralStore{
		codes:    make(map[string]*authCode),
		sessions: make(map[string]*ssoSession),
		clients:  make(map[string]*registeredClient),
	}
}

func (s *ephemeralStore) StoreCode(c *authCode) {
	s.mu.Lock()
	s.codes[c.Code] = c
	s.mu.Unlock()
}

// ConsumeCode atomically retrieves and deletes a code. Returns ErrNotFound or
// ErrExpired if the code is missing or stale.
func (s *ephemeralStore) ConsumeCode(code string) (*authCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.codes[code]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.codes, code)
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	return c, nil
}

func (s *ephemeralStore) StoreSession(sess *ssoSession) {
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
}

// LookupSession returns the session if it exists and has not expired.
func (s *ephemeralStore) LookupSession(id string) (*ssoSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil, false
	}
	return sess, true
}

func (s *ephemeralStore) DeleteSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// RegisterClient stores a dynamically registered OIDC client.
func (s *ephemeralStore) RegisterClient(c *registeredClient) {
	s.mu.Lock()
	s.clients[c.Domain+"\x00"+c.ClientID] = c
	s.mu.Unlock()
}

// LookupClient returns a dynamically registered client by domain and client ID.
func (s *ephemeralStore) LookupClient(domain, clientID string) (*registeredClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[domain+"\x00"+clientID]
	return c, ok
}

// SweepExpired drops codes and sessions with ExpiresAt at or before now.
func (s *ephemeralStore) SweepExpired(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.codes {
		if !now.Before(c.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	for k, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	return nil
}

// Close is a no-op for the in-memory store.
func (s *ephemeralStore) Close() error { return nil }

// generateToken returns a cryptographically random base64url-encoded string of
// n random bytes.
func generateToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
