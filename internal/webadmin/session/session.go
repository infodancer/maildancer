// Package session provides cookie-based session management for the webadmin.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	cookieName   = "webadmin_session"
	tokenLength  = 32
	csrfFormName = "csrf_token"
)

// Session represents an authenticated admin session.
type Session struct {
	ID        string
	Username  string
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
}

// IsExpired returns true if the session has exceeded the timeout.
func (s *Session) IsExpired(timeout time.Duration) bool {
	return time.Since(s.LastSeen) > timeout
}

// Store manages active sessions in memory.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
}

// NewStore creates a new session store with the given timeout.
func NewStore(timeout time.Duration) *Store {
	s := &Store{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
	// Start background cleanup
	go s.cleanup()
	return s
}

// Create creates a new session for the given username and sets the cookie.
func (s *Store) Create(w http.ResponseWriter, username string) (*Session, error) {
	id, err := generateToken()
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateToken()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:        id,
		Username:  username,
		CSRFToken: csrfToken,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.timeout.Seconds()),
	})

	return session, nil
}

// Get retrieves the session from the request cookie.
// Returns nil if no valid session exists or if it has expired.
func (s *Store) Get(r *http.Request) *Session {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}

	s.mu.RLock()
	session, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()

	if !ok {
		return nil
	}

	if session.IsExpired(s.timeout) {
		s.Delete(cookie.Value)
		return nil
	}

	// Update last seen
	s.mu.Lock()
	session.LastSeen = time.Now()
	s.mu.Unlock()

	return session
}

// Delete removes a session by ID and clears the cookie.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// Destroy removes the session associated with the request and clears the cookie.
func (s *Store) Destroy(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}

	s.Delete(cookie.Value)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// ValidateCSRF checks that the CSRF token in the form matches the session.
func (s *Store) ValidateCSRF(r *http.Request, session *Session) bool {
	token := r.FormValue(csrfFormName)
	if token == "" {
		// Also check the header for API requests
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" || session == nil {
		return false
	}
	return token == session.CSRFToken
}

// cleanup periodically removes expired sessions.
func (s *Store) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		for id, session := range s.sessions {
			if session.IsExpired(s.timeout) {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// generateToken creates a cryptographically random hex token.
func generateToken() (string, error) {
	b := make([]byte, tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CSRFFormName returns the form field name for CSRF tokens.
func CSRFFormName() string {
	return csrfFormName
}
