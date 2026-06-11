package authoidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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

// Signing key states. The schema CHECK constraint pins these values.
const (
	keyStateCurrent  = "current"
	keyStateRetiring = "retiring"
)

// Supported signing algorithms. JWA identifiers per RFC 7518 / RFC 8037.
// Add new strings here (e.g. "ML-DSA-65" when JWA finalises a PQC identifier)
// -- schema treats algorithm as TEXT, so no migration is required.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

// signingKeyRecord is the authoritative metadata for a signing key. The
// matching private key material lives on the filesystem at
// {data_dir}/{domain}/keys/{kid}.key with 0600 perms; the row here records
// which kid is current, which are retiring, and when retiring ones expire.
//
// RetiredAt and ExpiresAt are zero (time.Time{}) when State == "current".
type signingKeyRecord struct {
	Domain    string
	KID       string
	Algorithm string
	State     string
	CreatedAt time.Time
	RetiredAt time.Time
	ExpiresAt time.Time
}

// Store is the persistence contract for OIDC authorization codes, SSO sessions,
// and dynamically registered clients. Implementations must keep ConsumeCode
// atomic -- a single caller succeeds even under concurrent attempts.
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

	// --- signing keys (per docs/signing-key-rotation.md) ---

	// ListSigningKeys returns all signing-key records for a domain, in any
	// order. Both current and retiring keys are returned; callers filter as
	// needed.
	ListSigningKeys(domain string) ([]signingKeyRecord, error)

	// InsertSigningKey records a key as current. It is the first-time-setup
	// counterpart to RotateSigningKey: there must be no existing current key
	// for the domain or the call returns an error.
	InsertSigningKey(rec signingKeyRecord) error

	// RotateSigningKey atomically moves the existing current key for domain
	// into the retiring state (with retired_at=now and
	// expires_at=now+retention) and inserts the supplied record as the new
	// current key. If no current key exists, behaves like InsertSigningKey.
	RotateSigningKey(domain string, newKey signingKeyRecord, retention time.Duration) error

	// RevokeSigningKey marks the named key as expired immediately so the next
	// SweepExpiredSigningKeys call removes it. Operator-initiated; the caller
	// has decided to accept that any token still signed by this kid will fail
	// validation as soon as the row is gone from the DB.
	RevokeSigningKey(domain, kid string) error

	// SweepExpiredSigningKeys deletes retiring rows whose expires_at <= now
	// and returns the deleted records so the caller can unlink the
	// corresponding key files. Sweep is best-effort with respect to file
	// unlink; the DB row deletion is the authoritative state change.
	SweepExpiredSigningKeys(now time.Time) ([]signingKeyRecord, error)

	// Close releases any resources held by the store (open file handles,
	// background goroutines). Idempotent.
	Close() error
}

// ephemeralStore is an in-memory store for auth codes, SSO sessions, and
// registered clients. State is lost on process restart -- use only in tests or
// for deployments that explicitly do not require durability.
type ephemeralStore struct {
	mu          sync.Mutex
	codes       map[string]*authCode
	sessions    map[string]*ssoSession
	clients     map[string]*registeredClient // key: "domain\x00clientID"
	signingKeys map[string]*signingKeyRecord // key: "domain\x00kid"
}

func newEphemeralStore() *ephemeralStore {
	return &ephemeralStore{
		codes:       make(map[string]*authCode),
		sessions:    make(map[string]*ssoSession),
		clients:     make(map[string]*registeredClient),
		signingKeys: make(map[string]*signingKeyRecord),
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

// ListSigningKeys returns a snapshot copy of every signing key record for
// domain. Callers may inspect/modify the returned slice without holding the
// store lock.
func (s *ephemeralStore) ListSigningKeys(domain string) ([]signingKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []signingKeyRecord
	for _, rec := range s.signingKeys {
		if rec.Domain == domain {
			out = append(out, *rec)
		}
	}
	return out, nil
}

// InsertSigningKey inserts a new current key when none exists for the domain.
func (s *ephemeralStore) InsertSigningKey(rec signingKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.signingKeys {
		if r.Domain == rec.Domain && r.State == keyStateCurrent {
			return fmt.Errorf("current signing key already exists for domain %s", rec.Domain)
		}
	}
	cp := rec
	s.signingKeys[rec.Domain+"\x00"+rec.KID] = &cp
	return nil
}

// RotateSigningKey moves the existing current key to retiring and inserts
// newKey as the new current. The operation is atomic relative to other
// callers via the store mutex.
func (s *ephemeralStore) RotateSigningKey(domain string, newKey signingKeyRecord, retention time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.signingKeys[domain+"\x00"+newKey.KID]; exists {
		return fmt.Errorf("signing key %s already exists for domain %s", newKey.KID, domain)
	}
	now := time.Now()
	for _, r := range s.signingKeys {
		if r.Domain == domain && r.State == keyStateCurrent {
			r.State = keyStateRetiring
			r.RetiredAt = now
			r.ExpiresAt = now.Add(retention)
		}
	}
	cp := newKey
	s.signingKeys[domain+"\x00"+newKey.KID] = &cp
	return nil
}

// RevokeSigningKey marks a key as expired immediately (expires_at = epoch 1
// so the next sweep removes it). Returns an error if the key does not exist.
func (s *ephemeralStore) RevokeSigningKey(domain, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.signingKeys[domain+"\x00"+kid]
	if !ok {
		return fmt.Errorf("signing key %s not found for domain %s", kid, domain)
	}
	rec.State = keyStateRetiring
	rec.RetiredAt = time.Now()
	rec.ExpiresAt = time.Unix(1, 0) // sweep will delete on next pass
	return nil
}

// SweepExpiredSigningKeys removes retiring rows whose expires_at <= now and
// returns the deleted records.
func (s *ephemeralStore) SweepExpiredSigningKeys(now time.Time) ([]signingKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []signingKeyRecord
	for k, r := range s.signingKeys {
		if r.State == keyStateRetiring && !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
			removed = append(removed, *r)
			delete(s.signingKeys, k)
		}
	}
	return removed, nil
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
