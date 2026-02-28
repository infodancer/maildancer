// Package backend implements the IMAP session using the msgstore interface.
package backend

import (
	"context"
	"log/slog"
	"strings"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/logging"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/msgstore"
)

// Session implements imapserver.Session backed by the msgstore interface.
type Session struct {
	conn        *imapserver.Conn
	cfg         *config.Config
	authRouter  *domain.AuthRouter
	store       msgstore.MessageStore
	folderStore msgstore.FolderStore

	username   string
	mailbox    string // user's mailbox identifier from auth
	userDomain string
	collector  metrics.Collector
	logger     *slog.Logger

	// Selected state
	selectedMailbox string
	messages        []msgstore.MessageInfo
	tracker         *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker
	readOnly        bool
}

// NewSession creates a new IMAP session for the given connection.
func NewSession(conn *imapserver.Conn, cfg *config.Config, authRouter *domain.AuthRouter, store msgstore.MessageStore, collector metrics.Collector, logger *slog.Logger) *Session {
	var folderStore msgstore.FolderStore
	if store != nil {
		folderStore, _ = store.(msgstore.FolderStore)
	}
	return &Session{
		conn:        conn,
		cfg:         cfg,
		authRouter:  authRouter,
		store:       store,
		folderStore: folderStore,
		collector:   collector,
		logger:      logging.WithConnection(logger, conn.NetConn().RemoteAddr().String()),
	}
}

// Login authenticates the user.
func (s *Session) Login(username, password string) error {
	ctx := context.Background()
	result, err := s.authRouter.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		s.logger.Info("login failed", "username", username, "error", err)
		s.collector.AuthAttempt(extractDomain(username), false)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Authentication failed",
		}
	}
	s.username = username
	s.userDomain = extractDomain(username)
	s.mailbox = result.Session.User.Mailbox
	if result.Domain != nil && result.Domain.MessageStore != nil {
		s.store = result.Domain.MessageStore
		s.folderStore, _ = result.Domain.MessageStore.(msgstore.FolderStore)
	}
	s.collector.AuthAttempt(s.userDomain, true)
	s.logger.Info("login success", "username", username)
	return nil
}

// Poll checks for mailbox updates.
func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.sessionTracker == nil {
		return nil
	}
	return s.sessionTracker.Poll(w, allowExpunge)
}

// Idle waits for mailbox updates.
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.sessionTracker == nil {
		return nil
	}
	return s.sessionTracker.Idle(w, stop)
}

// Unselect closes the currently selected mailbox without expunging.
func (s *Session) Unselect() error {
	s.unselect()
	return nil
}

// Close ends the session and releases resources.
func (s *Session) Close() error {
	s.unselect()
	s.collector.ConnectionClosed()
	return nil
}

// Subscribe is a no-op (subscription state not tracked).
func (s *Session) Subscribe(_ string) error {
	return nil
}

// Unsubscribe is a no-op.
func (s *Session) Unsubscribe(_ string) error {
	return nil
}

// --- Internal helpers ---

func (s *Session) unselect() {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
		s.sessionTracker = nil
	}
	s.tracker = nil
	s.messages = nil
	s.selectedMailbox = ""
}

func extractDomain(username string) string {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[idx+1:]
	}
	return "local"
}

// isValidMailboxName returns false for names with path-traversal sequences.
func isValidMailboxName(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || strings.HasSuffix(name, "/..") {
		return false
	}
	return true
}

// hasFlag checks if a flag is present in a slice of IMAP flag strings.
func hasFlag(flags []string, flag imap.Flag) bool {
	fs := string(flag)
	for _, f := range flags {
		if f == fs {
			return true
		}
	}
	return false
}

// applyStoreFlagsStr applies a StoreFlags operation to an existing set of IMAP flag strings.
func applyStoreFlagsStr(current []string, store *imap.StoreFlags) []string {
	switch store.Op {
	case imap.StoreFlagsSet:
		result := make([]string, len(store.Flags))
		for i, f := range store.Flags {
			result[i] = string(f)
		}
		return result

	case imap.StoreFlagsAdd:
		result := make([]string, len(current))
		copy(result, current)
		for _, f := range store.Flags {
			fs := string(f)
			found := false
			for _, existing := range result {
				if existing == fs {
					found = true
					break
				}
			}
			if !found {
				result = append(result, fs)
			}
		}
		return result

	case imap.StoreFlagsDel:
		var result []string
		for _, existing := range current {
			remove := false
			for _, f := range store.Flags {
				if existing == string(f) {
					remove = true
					break
				}
			}
			if !remove {
				result = append(result, existing)
			}
		}
		return result
	}
	return current
}

func (s *Session) resolveNumSet(numSet imap.NumSet) []int {
	var indices []int
	switch ns := numSet.(type) {
	case imap.SeqSet:
		nums, ok := ns.Nums()
		if !ok {
			for i := range s.messages {
				indices = append(indices, i)
			}
			return indices
		}
		for _, n := range nums {
			indices = append(indices, int(n)-1)
		}
	case imap.UIDSet:
		uids, ok := ns.Nums()
		if !ok {
			for i := range s.messages {
				indices = append(indices, i)
			}
			return indices
		}
		for _, u := range uids {
			indices = append(indices, int(u)-1)
		}
	}
	return indices
}
