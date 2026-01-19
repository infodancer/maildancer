package pop3

import (
	"crypto/tls"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// State represents the current state in the POP3 state machine.
type State int

const (
	// StateAuthorization is the initial state where authentication is required.
	StateAuthorization State = iota

	// StateTransaction is the state after successful authentication.
	StateTransaction

	// StateUpdate is the state after QUIT from Transaction (for committing changes).
	StateUpdate
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateAuthorization:
		return "AUTHORIZATION"
	case StateTransaction:
		return "TRANSACTION"
	case StateUpdate:
		return "UPDATE"
	default:
		return "UNKNOWN"
	}
}

// TLSState represents the current TLS encryption state of the connection.
type TLSState int

const (
	// TLSStateNone indicates no TLS protection (ModePop3 before STARTTLS).
	TLSStateNone TLSState = iota

	// TLSStateActive indicates TLS is active (after STARTTLS or ModePop3s implicit).
	TLSStateActive
)

// String returns the string representation of the TLS state.
func (ts TLSState) String() string {
	switch ts {
	case TLSStateNone:
		return "NONE"
	case TLSStateActive:
		return "ACTIVE"
	default:
		return "UNKNOWN"
	}
}

// Session represents a POP3 session with state tracking.
type Session struct {
	// State machine
	state    State
	tlsState TLSState

	// Configuration
	hostname     string
	listenerMode config.ListenerMode
	tlsConfig    *tls.Config

	// Authentication state
	username    string
	authSession *auth.AuthSession
}

// NewSession creates a new POP3 session.
func NewSession(hostname string, mode config.ListenerMode, tlsConfig *tls.Config, isTLS bool) *Session {
	// Determine initial TLS state based on listener mode and connection state
	tlsState := TLSStateNone
	if mode == config.ModePop3s || isTLS {
		tlsState = TLSStateActive
	}

	return &Session{
		state:        StateAuthorization,
		tlsState:     tlsState,
		hostname:     hostname,
		listenerMode: mode,
		tlsConfig:    tlsConfig,
	}
}

// State returns the current POP3 state.
func (s *Session) State() State {
	return s.state
}

// TLSState returns the current TLS state.
func (s *Session) TLSState() TLSState {
	return s.tlsState
}

// SetTLSActive marks the connection as using TLS.
// Should be called after successful STARTTLS upgrade.
func (s *Session) SetTLSActive() {
	s.tlsState = TLSStateActive
}

// IsTLSActive returns true if TLS is currently active.
func (s *Session) IsTLSActive() bool {
	return s.tlsState == TLSStateActive
}

// CanSTLS returns true if STLS command is available.
// STLS is only available in StateAuthorization on ModePop3 listeners before TLS.
func (s *Session) CanSTLS() bool {
	return s.state == StateAuthorization &&
		s.listenerMode == config.ModePop3 &&
		s.tlsState == TLSStateNone &&
		s.tlsConfig != nil
}

// TLSConfig returns the TLS configuration for STARTTLS.
func (s *Session) TLSConfig() *tls.Config {
	return s.tlsConfig
}

// SetUsername stores the username from the USER command.
func (s *Session) SetUsername(username string) {
	s.username = username
}

// Username returns the stored username.
func (s *Session) Username() string {
	return s.username
}

// SetAuthenticated transitions to StateTransaction after successful authentication.
// Stores the AuthSession for later use.
func (s *Session) SetAuthenticated(authSession *auth.AuthSession) {
	s.state = StateTransaction
	s.authSession = authSession
}

// IsAuthenticated returns true if in StateTransaction or StateUpdate.
func (s *Session) IsAuthenticated() bool {
	return s.state == StateTransaction || s.state == StateUpdate
}

// AuthSession returns the authentication session, or nil if not authenticated.
func (s *Session) AuthSession() *auth.AuthSession {
	return s.authSession
}

// EnterUpdate transitions to StateUpdate (called when QUIT is received in Transaction).
func (s *Session) EnterUpdate() {
	if s.state == StateTransaction {
		s.state = StateUpdate
	}
}

// Capabilities returns the list of capabilities for this session.
// Capabilities change based on TLS state and listener mode.
func (s *Session) Capabilities() []string {
	caps := []string{"TOP", "UIDL", "RESP-CODES"}

	// Only advertise USER if TLS is active
	if s.tlsState == TLSStateActive {
		caps = append([]string{"USER"}, caps...)
	}

	// Only advertise STLS if it's available
	if s.CanSTLS() {
		caps = append(caps, "STLS")
	}

	return caps
}

// Cleanup performs cleanup when the session ends.
// Zeros sensitive key material if authenticated.
func (s *Session) Cleanup() {
	if s.authSession != nil {
		s.authSession.Clear()
		s.authSession = nil
	}
}
