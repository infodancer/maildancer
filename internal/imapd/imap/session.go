package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/msgstore"
)

// State represents the current state in the IMAP state machine.
type State int

const (
	// StateNotAuthenticated is the initial state where authentication is required.
	StateNotAuthenticated State = iota

	// StateAuthenticated is the state after successful authentication.
	StateAuthenticated

	// StateSelected is the state after a mailbox has been selected.
	StateSelected

	// StateLogout is the terminal state.
	StateLogout
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateNotAuthenticated:
		return "NOT_AUTHENTICATED"
	case StateAuthenticated:
		return "AUTHENTICATED"
	case StateSelected:
		return "SELECTED"
	case StateLogout:
		return "LOGOUT"
	default:
		return "UNKNOWN"
	}
}

// Session represents an IMAP session with state tracking.
type Session struct {
	// State machine
	state    State
	readOnly bool // true if EXAMINE was used

	// Configuration
	hostname     string
	listenerMode config.ListenerMode
	tlsConfig    *tls.Config

	// Authentication state
	username    string
	authSession *auth.AuthSession
	userDomain  string // extracted domain for metrics

	// Storage
	store           msgstore.MessageStore
	folderStore     msgstore.FolderStore // type-asserted from store, may be nil
	mailbox         string              // user's base mailbox path
	selectedMailbox string              // currently selected mailbox/folder name
	messages        []msgstore.MessageInfo
	recentCount     int
	uidValidity     uint32
	sessionFlags    map[int][]string // per-message session flags, keyed by 1-based seqnum

	// Metrics & logging
	collector metrics.Collector
	logger    *slog.Logger
}

// NewSession creates a new IMAP session.
func NewSession(hostname string, mode config.ListenerMode, tlsConfig *tls.Config, isTLS bool, store msgstore.MessageStore, collector metrics.Collector, logger *slog.Logger) *Session {
	s := &Session{
		state:        StateNotAuthenticated,
		hostname:     hostname,
		listenerMode: mode,
		tlsConfig:    tlsConfig,
		store:        store,
		collector:    collector,
		logger:       logger,
		// Use a fixed UIDVALIDITY based on server start time
		uidValidity:  uint32(time.Now().Unix() & 0x7FFFFFFF),
		sessionFlags: make(map[int][]string),
	}

	// Check if the store supports folder operations
	if fs, ok := store.(msgstore.FolderStore); ok {
		s.folderStore = fs
	}

	return s
}

// State returns the current IMAP state.
func (s *Session) State() State {
	return s.state
}

// IsReadOnly returns true if the selected mailbox is read-only.
func (s *Session) IsReadOnly() bool {
	return s.readOnly
}

// Hostname returns the server hostname.
func (s *Session) Hostname() string {
	return s.hostname
}

// IsTLSAvailable returns true if TLS configuration is present.
func (s *Session) IsTLSAvailable() bool {
	return s.tlsConfig != nil
}

// TLSConfig returns the TLS configuration.
func (s *Session) TLSConfig() *tls.Config {
	return s.tlsConfig
}

// ListenerMode returns the listener mode.
func (s *Session) ListenerMode() config.ListenerMode {
	return s.listenerMode
}

// CanSTARTTLS returns true if STARTTLS is available.
// STARTTLS is only available in ModeImap (not ModeImaps) and when TLS config is present.
func (s *Session) CanSTARTTLS() bool {
	return s.listenerMode == config.ModeImap && s.tlsConfig != nil
}

// SetAuthenticated transitions to StateAuthenticated after successful authentication.
func (s *Session) SetAuthenticated(authSession *auth.AuthSession, username string, domainResult *domain.Domain, store msgstore.MessageStore) {
	s.state = StateAuthenticated
	s.authSession = authSession
	s.username = username
	s.userDomain = extractDomain(username)

	if authSession != nil && authSession.User != nil {
		s.mailbox = authSession.User.Mailbox
	}

	// Use domain-specific store if available
	if domainResult != nil && domainResult.MessageStore != nil {
		s.store = domainResult.MessageStore
	} else if store != nil {
		s.store = store
	}

	// Re-check folder store
	if fs, ok := s.store.(msgstore.FolderStore); ok {
		s.folderStore = fs
	}
}

// SelectMailbox selects a mailbox and loads its messages.
func (s *Session) SelectMailbox(ctx context.Context, name string, readOnly bool) error {
	if s.store == nil {
		return fmt.Errorf("no message store available")
	}

	var messages []msgstore.MessageInfo
	var err error

	folder := mailboxToFolder(name)

	if folder == "" {
		// INBOX
		messages, err = s.store.List(ctx, s.mailbox)
	} else if s.folderStore != nil {
		messages, err = s.folderStore.ListInFolder(ctx, s.mailbox, folder)
	} else {
		return fmt.Errorf("folder operations not supported")
	}

	if err != nil {
		return err
	}

	s.state = StateSelected
	s.readOnly = readOnly
	s.selectedMailbox = name
	s.messages = messages
	s.sessionFlags = make(map[int][]string)

	// Initialize session flags from stored flags
	for i, msg := range s.messages {
		s.sessionFlags[i+1] = append([]string(nil), msg.Flags...)
	}

	// Count recent messages
	s.recentCount = 0
	for _, msg := range s.messages {
		if HasFlag(msg.Flags, FlagRecent) {
			s.recentCount++
		}
	}

	return nil
}

// DeselectMailbox deselects the current mailbox.
func (s *Session) DeselectMailbox() {
	s.state = StateAuthenticated
	s.selectedMailbox = ""
	s.messages = nil
	s.sessionFlags = make(map[int][]string)
	s.recentCount = 0
	s.readOnly = false
}

// SetLogout transitions to logout state.
func (s *Session) SetLogout() {
	s.state = StateLogout
}

// Username returns the authenticated username.
func (s *Session) Username() string {
	return s.username
}

// UserDomain returns the domain portion of the username for metrics.
func (s *Session) UserDomain() string {
	return s.userDomain
}

// Mailbox returns the user's base mailbox path.
func (s *Session) Mailbox() string {
	return s.mailbox
}

// SelectedMailbox returns the currently selected mailbox name.
func (s *Session) SelectedMailbox() string {
	return s.selectedMailbox
}

// Store returns the message store.
func (s *Session) Store() msgstore.MessageStore {
	return s.store
}

// FolderStore returns the folder store, or nil if not supported.
func (s *Session) FolderStore() msgstore.FolderStore {
	return s.folderStore
}

// MessageCount returns the number of messages in the selected mailbox.
func (s *Session) MessageCount() int {
	return len(s.messages)
}

// RecentCount returns the number of recent messages.
func (s *Session) RecentCount() int {
	return s.recentCount
}

// UIDValidity returns the UIDVALIDITY value.
func (s *Session) UIDValidity() uint32 {
	return s.uidValidity
}

// UIDNext returns the next UID value (max UID + 1).
func (s *Session) UIDNext() uint32 {
	if len(s.messages) == 0 {
		return 1
	}
	var maxUID uint32
	for i := range s.messages {
		uid := s.MessageUID(i + 1)
		if uid > maxUID {
			maxUID = uid
		}
	}
	return maxUID + 1
}

// UnseenCount returns the count of messages without the \Seen flag.
func (s *Session) UnseenCount() int {
	count := 0
	for i := range s.messages {
		flags := s.GetFlags(i + 1)
		if !HasFlag(flags, FlagSeen) {
			count++
		}
	}
	return count
}

// FirstUnseen returns the sequence number of the first unseen message, or 0 if all seen.
func (s *Session) FirstUnseen() int {
	for i := range s.messages {
		flags := s.GetFlags(i + 1)
		if !HasFlag(flags, FlagSeen) {
			return i + 1
		}
	}
	return 0
}

// GetMessage returns message info by 1-based sequence number.
func (s *Session) GetMessage(seqNum int) *msgstore.MessageInfo {
	if seqNum < 1 || seqNum > len(s.messages) {
		return nil
	}
	return &s.messages[seqNum-1]
}

// MessageUID converts a 1-based sequence number to a UID (uint32).
// Uses a hash of the string UID to produce a stable uint32.
func (s *Session) MessageUID(seqNum int) uint32 {
	if seqNum < 1 || seqNum > len(s.messages) {
		return 0
	}
	return uidFromString(s.messages[seqNum-1].UID)
}

// FindByUID finds the sequence number for a given UID.
// Returns 0 if not found.
func (s *Session) FindByUID(uid uint32) int {
	for i := range s.messages {
		if uidFromString(s.messages[i].UID) == uid {
			return i + 1
		}
	}
	return 0
}

// GetFlags returns the current flags for a message (1-based sequence number).
func (s *Session) GetFlags(seqNum int) []string {
	if flags, ok := s.sessionFlags[seqNum]; ok {
		return flags
	}
	if seqNum >= 1 && seqNum <= len(s.messages) {
		return s.messages[seqNum-1].Flags
	}
	return nil
}

// SetFlags replaces all flags for a message.
func (s *Session) SetFlags(seqNum int, flags []string) {
	s.sessionFlags[seqNum] = flags
}

// AddFlags adds flags to a message.
func (s *Session) AddFlags(seqNum int, flags []string) {
	current := s.GetFlags(seqNum)
	for _, f := range flags {
		current = AddFlag(current, f)
	}
	s.sessionFlags[seqNum] = current
}

// RemoveFlags removes flags from a message.
func (s *Session) RemoveFlags(seqNum int, flags []string) {
	current := s.GetFlags(seqNum)
	for _, f := range flags {
		current = RemoveFlag(current, f)
	}
	s.sessionFlags[seqNum] = current
}

// ExpungeDeleted removes messages flagged as \Deleted.
// Returns the sequence numbers of expunged messages (in ascending order).
func (s *Session) ExpungeDeleted(ctx context.Context) ([]int, error) {
	var expunged []int

	folder := mailboxToFolder(s.selectedMailbox)

	for i := len(s.messages) - 1; i >= 0; i-- {
		seqNum := i + 1
		flags := s.GetFlags(seqNum)
		if HasFlag(flags, FlagDeleted) {
			uid := s.messages[i].UID

			// Delete from store
			var err error
			if folder == "" {
				err = s.store.Delete(ctx, s.mailbox, uid)
			} else if s.folderStore != nil {
				err = s.folderStore.DeleteInFolder(ctx, s.mailbox, folder, uid)
			}
			if err != nil {
				s.logger.Error("failed to delete message", "uid", uid, "error", err.Error())
				continue
			}

			expunged = append([]int{seqNum}, expunged...)

			// Remove from messages slice
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			delete(s.sessionFlags, seqNum)

			// Renumber session flags for messages after the removed one
			newFlags := make(map[int][]string)
			for k, v := range s.sessionFlags {
				if k > seqNum {
					newFlags[k-1] = v
				} else {
					newFlags[k] = v
				}
			}
			s.sessionFlags = newFlags
		}
	}

	// Expunge from store
	if len(expunged) > 0 {
		var err error
		if folder == "" {
			err = s.store.Expunge(ctx, s.mailbox)
		} else if s.folderStore != nil {
			err = s.folderStore.ExpungeFolder(ctx, s.mailbox, folder)
		}
		if err != nil {
			s.logger.Error("failed to expunge mailbox", "error", err.Error())
		}
	}

	return expunged, nil
}

// Capabilities returns the capability list for the current session state.
func (s *Session) Capabilities(isTLS bool) []string {
	caps := []string{"IMAP4rev1"}

	if !isTLS && s.CanSTARTTLS() {
		caps = append(caps, "STARTTLS")
	}

	if isTLS {
		caps = append(caps, "AUTH=PLAIN")
	}

	caps = append(caps, "LITERAL+", "IDLE")

	return caps
}

// Cleanup performs cleanup when the session ends.
func (s *Session) Cleanup() {
	if s.authSession != nil {
		s.authSession.Clear()
		s.authSession = nil
	}
}

// Collector returns the metrics collector.
func (s *Session) Collector() metrics.Collector {
	return s.collector
}

// Logger returns the session logger.
func (s *Session) Logger() *slog.Logger {
	return s.logger
}

// mailboxToFolder converts an IMAP mailbox name to a folder name.
// INBOX maps to empty string (root mailbox). Other names map directly.
func mailboxToFolder(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return ""
	}
	return name
}

// uidFromString converts a string UID to a uint32 using FNV-1a hash.
func uidFromString(s string) uint32 {
	// FNV-1a hash
	const (
		offset32 = uint32(2166136261)
		prime32  = uint32(16777619)
	)
	hash := offset32
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	// Ensure non-zero (IMAP UIDs must be positive)
	if hash == 0 {
		hash = 1
	}
	return hash
}

// extractDomain extracts the domain part from a username.
func extractDomain(username string) string {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[idx+1:]
	}
	return "unknown"
}
