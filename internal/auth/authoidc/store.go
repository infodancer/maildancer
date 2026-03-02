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

// memStore is an in-memory store for auth codes and SSO sessions.
// State is ephemeral — lost on process restart, which is acceptable for
// a mail auth service where re-authentication is low-friction.
type memStore struct {
	mu       sync.Mutex
	codes    map[string]*authCode
	sessions map[string]*ssoSession
	clients  map[string]*registeredClient // key: "domain\x00clientID"
}

func newMemStore() *memStore {
	return &memStore{
		codes:    make(map[string]*authCode),
		sessions: make(map[string]*ssoSession),
		clients:  make(map[string]*registeredClient),
	}
}

func (s *memStore) StoreCode(c *authCode) {
	s.mu.Lock()
	s.codes[c.Code] = c
	s.mu.Unlock()
}

// ConsumeCode atomically retrieves and deletes a code. Returns ErrNotFound or
// ErrExpired if the code is missing or stale.
func (s *memStore) ConsumeCode(code string) (*authCode, error) {
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

func (s *memStore) StoreSession(sess *ssoSession) {
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
}

// LookupSession returns the session if it exists and has not expired.
func (s *memStore) LookupSession(id string) (*ssoSession, bool) {
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

func (s *memStore) DeleteSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// RegisterClient stores a dynamically registered OIDC client.
func (s *memStore) RegisterClient(c *registeredClient) {
	s.mu.Lock()
	s.clients[c.Domain+"\x00"+c.ClientID] = c
	s.mu.Unlock()
}

// LookupClient returns a dynamically registered client by domain and client ID.
func (s *memStore) LookupClient(domain, clientID string) (*registeredClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[domain+"\x00"+clientID]
	return c, ok
}

// generateToken returns a cryptographically random base64url-encoded string of
// n random bytes.
func generateToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
