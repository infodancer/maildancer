package pop3

import (
	"context"
	"crypto/tls"

	"github.com/emersion/go-sasl"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
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

	// SASL state (for multi-step authentication exchanges)
	saslServer sasl.Server // Active SASL server during exchange
	saslMech   string      // Current mechanism name

	// Transaction state (mailbox data)
	mailbox     string                 // User's mailbox path
	store       msgstore.MessageStore  // Reference to message store
	messageList []msgstore.MessageInfo // Loaded after auth
	deletedSet  map[int]bool           // 1-based message numbers marked deleted
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

// SetSASLServer sets the active SASL server for a multi-step exchange.
func (s *Session) SetSASLServer(mech string, server sasl.Server) {
	s.saslMech = mech
	s.saslServer = server
}

// SASLServer returns the active SASL server, or nil if none.
func (s *Session) SASLServer() sasl.Server {
	return s.saslServer
}

// SASLMech returns the current SASL mechanism name.
func (s *Session) SASLMech() string {
	return s.saslMech
}

// ClearSASL clears the SASL state after completion or cancellation.
func (s *Session) ClearSASL() {
	s.saslServer = nil
	s.saslMech = ""
}

// IsSASLInProgress returns true if a SASL exchange is in progress.
func (s *Session) IsSASLInProgress() bool {
	return s.saslServer != nil
}

// Capabilities returns the list of capabilities for this session.
// Capabilities change based on TLS state and listener mode.
func (s *Session) Capabilities() []string {
	caps := []string{"TOP", "UIDL", "RESP-CODES"}

	// Only advertise USER if TLS is active
	if s.tlsState == TLSStateActive {
		caps = append([]string{"USER"}, caps...)
	}

	// Only advertise SASL PLAIN if TLS is active
	if s.tlsState == TLSStateActive {
		caps = append(caps, "SASL PLAIN")
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

// InitializeMailbox loads the message list for the authenticated user's mailbox.
// Should be called after successful authentication.
func (s *Session) InitializeMailbox(ctx context.Context, store msgstore.MessageStore) error {
	if s.authSession == nil || s.authSession.User == nil {
		return ErrMailboxNotInitialized
	}

	s.mailbox = s.authSession.User.Mailbox
	s.store = store
	s.deletedSet = make(map[int]bool)

	// Load message list
	messages, err := store.List(ctx, s.mailbox)
	if err != nil {
		return err
	}
	s.messageList = messages

	return nil
}

// MessageCount returns the count of non-deleted messages.
func (s *Session) MessageCount() int {
	if s.messageList == nil {
		return 0
	}
	count := 0
	for i := range s.messageList {
		if !s.deletedSet[i+1] { // 1-based numbering
			count++
		}
	}
	return count
}

// TotalSize returns the total size of non-deleted messages in bytes.
func (s *Session) TotalSize() int64 {
	if s.messageList == nil {
		return 0
	}
	var total int64
	for i, msg := range s.messageList {
		if !s.deletedSet[i+1] { // 1-based numbering
			total += msg.Size
		}
	}
	return total
}

// GetMessage returns message info by 1-based message number.
// Returns an error if the message doesn't exist or is deleted.
func (s *Session) GetMessage(msgNum int) (*msgstore.MessageInfo, error) {
	if s.messageList == nil {
		return nil, ErrMailboxNotInitialized
	}
	if msgNum < 1 || msgNum > len(s.messageList) {
		return nil, ErrNoSuchMessage
	}
	if s.deletedSet[msgNum] {
		return nil, ErrMessageDeleted
	}
	return &s.messageList[msgNum-1], nil
}

// MarkDeleted marks a message for deletion by 1-based message number.
func (s *Session) MarkDeleted(msgNum int) error {
	if s.messageList == nil {
		return ErrMailboxNotInitialized
	}
	if msgNum < 1 || msgNum > len(s.messageList) {
		return ErrNoSuchMessage
	}
	if s.deletedSet[msgNum] {
		return ErrMessageDeleted
	}
	s.deletedSet[msgNum] = true
	return nil
}

// ResetDeletions clears all deletion marks (RSET command).
func (s *Session) ResetDeletions() {
	s.deletedSet = make(map[int]bool)
}

// GetDeletedUIDs returns the UIDs of messages marked for deletion.
func (s *Session) GetDeletedUIDs() []string {
	if s.messageList == nil {
		return nil
	}
	var uids []string
	for msgNum := range s.deletedSet {
		if msgNum >= 1 && msgNum <= len(s.messageList) {
			uids = append(uids, s.messageList[msgNum-1].UID)
		}
	}
	return uids
}

// Store returns the message store for this session.
func (s *Session) Store() msgstore.MessageStore {
	return s.store
}

// Mailbox returns the mailbox path for this session.
func (s *Session) Mailbox() string {
	return s.mailbox
}

// AllMessages returns iterating info for all messages (for LIST/UIDL).
// Returns slice of (msgNum, msgInfo) where msgNum is 1-based.
func (s *Session) AllMessages() []struct {
	MsgNum int
	Info   msgstore.MessageInfo
} {
	if s.messageList == nil {
		return nil
	}
	var result []struct {
		MsgNum int
		Info   msgstore.MessageInfo
	}
	for i, msg := range s.messageList {
		if !s.deletedSet[i+1] {
			result = append(result, struct {
				MsgNum int
				Info   msgstore.MessageInfo
			}{MsgNum: i + 1, Info: msg})
		}
	}
	return result
}
