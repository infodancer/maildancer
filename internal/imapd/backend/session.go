// Package backend implements the IMAP session using the msgstore interface.
package backend

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/imapd/notify"
	"github.com/infodancer/maildancer/msgstore"
	storeerrors "github.com/infodancer/maildancer/msgstore/errors"
)

// keepaliveRPCTimeout bounds a single IDLE-time keepalive RPC. Set short so
// that a hung upstream doesn't keep the goroutine alive past IDLE teardown.
const keepaliveRPCTimeout = 10 * time.Second

// rescanner is satisfied by stores that support incremental rescan (IDLE).
type rescanner interface {
	Rescan() ([]msgstore.MessageInfo, error)
}

// Session implements imapserver.Session backed by the msgstore interface.
type Session struct {
	conn        *imapserver.Conn
	cfg         *config.Config
	store       msgstore.MessageStore
	folderStore msgstore.FolderStore
	smClient    *SessionManagerClient

	username   string
	mailbox    string // user's mailbox identifier from auth
	userDomain string
	collector  metrics.Collector
	logger     *slog.Logger

	// Spam learning (nil when disabled)
	learner *spamLearner

	// Redis new-mail notifications (nil when disabled)
	subscriber   *notify.Subscriber
	subscription *notify.Subscription

	// keepaliveInterval is how often to send a no-op RPC during IDLE to keep
	// the upstream mail-session subprocess from reaping. Zero disables.
	keepaliveInterval time.Duration

	// Selected state
	selectedMailbox string
	messages        []msgstore.MessageInfo
	uidIndex        map[imap.UID]int // UID → message index, built on Select
	tracker         *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker
	readOnly        bool
}

// NewSession creates a new IMAP session for the given connection.
func NewSession(conn *imapserver.Conn, cfg *config.Config, smClient *SessionManagerClient, subscriber *notify.Subscriber, collector metrics.Collector, logger *slog.Logger) *Session {
	var learner *spamLearner
	if cfg.Rspamd.Controller != "" {
		learner = newSpamLearner(cfg.Rspamd.Controller, "")
	}

	return &Session{
		conn:              conn,
		cfg:               cfg,
		smClient:          smClient,
		learner:           learner,
		subscriber:        subscriber,
		collector:         collector,
		logger:            logging.WithConnection(logger, conn.NetConn().RemoteAddr().String()),
		keepaliveInterval: cfg.Timeouts.SessionKeepaliveInterval(),
	}
}

// Login authenticates the user via the session-manager service.
func (s *Session) Login(username, password string) error {
	ctx := context.Background()
	token, mailbox, err := s.smClient.Login(ctx, username, password)
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
	s.mailbox = mailbox

	smStore := newSessionManagerStore(s.smClient, token)
	s.store = smStore
	s.folderStore = smStore

	// Ensure default folders exist (idempotent).
	s.ensureDefaultFolders()

	// Subscribe to Redis new-mail notifications for this user.
	if s.subscriber != nil {
		s.subscription = s.subscriber.Subscribe(ctx, username)
	}

	s.collector.AuthAttempt(s.userDomain, true)
	s.logger.Info("login success", "username", username, "via", "session-manager")
	return nil
}

// ensureDefaultFolders creates all default IMAP folders if they don't exist.
func (s *Session) ensureDefaultFolders() {
	ctx := context.Background()
	for _, spec := range msgstore.DefaultFolders {
		if err := s.folderStore.CreateFolder(ctx, s.mailbox, spec.Name); err != nil {
			if err != storeerrors.ErrFolderExists {
				s.logger.Warn("default folder creation failed", "folder", spec.Name, "error", err)
			}
		}
	}
}

// Poll checks for mailbox updates.
func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.sessionTracker == nil {
		return nil
	}
	return s.sessionTracker.Poll(w, allowExpunge)
}

// Idle waits for mailbox updates.
// When Redis notifications are available and the store supports RESCAN,
// incoming notifications for the selected folder trigger a rescan and
// update the tracker so the client receives * EXISTS.
//
// A keepalive goroutine runs for the lifetime of the IDLE, periodically
// invoking a no-op RPC against session-manager so the upstream mail-session
// subprocess doesn't reap itself during long IDLE periods (see issue #52).
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.sessionTracker == nil {
		return nil
	}

	done := make(chan struct{})
	defer close(done)
	if s.keepaliveInterval > 0 && s.selectedMailbox != "" && s.folderStore != nil {
		go s.runIdleKeepalive(done)
	}

	// If no Redis subscription, fall back to the standard tracker-only idle.
	if s.subscription == nil {
		return s.sessionTracker.Idle(w, stop)
	}

	rs, _ := s.store.(rescanner)

	for {
		select {
		case <-stop:
			return s.sessionTracker.Poll(w, true)
		case msg, ok := <-s.subscription.C:
			if !ok {
				// Channel closed, fall back to blocking idle.
				return s.sessionTracker.Idle(w, stop)
			}
			// Only trigger rescan if the notified folder matches the selected mailbox.
			if !strings.EqualFold(msg.Payload, s.selectedMailbox) {
				continue
			}
			if rs == nil {
				continue
			}
			newMsgs, err := rs.Rescan()
			if err != nil {
				s.logger.Warn("rescan after notification failed", "error", err)
				continue
			}
			if len(newMsgs) > 0 {
				s.messages = append(s.messages, newMsgs...)
				s.buildUIDIndex()
				s.tracker.QueueNumMessages(uint32(len(s.messages)))
				if err := s.sessionTracker.Poll(w, false); err != nil {
					return err
				}
			}
		}
	}
}

// runIdleKeepalive periodically issues a cheap RPC against the upstream store
// while an IDLE is active, preventing mail-session's idle interceptor from
// reaping the session. Exits when done is closed (Idle returning) or when the
// RPC fails irrecoverably — a failure is logged but the loop continues, since
// recovery is the next rescan/operation's responsibility, not the heartbeat's.
func (s *Session) runIdleKeepalive(done <-chan struct{}) {
	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), keepaliveRPCTimeout)
			_, err := s.folderStore.UIDValidity(ctx, s.mailbox, s.selectedMailbox)
			cancel()
			if err != nil {
				s.logger.Warn("idle keepalive failed", "error", err)
			}
		}
	}
}

// Unselect closes the currently selected mailbox without expunging.
func (s *Session) Unselect() error {
	s.unselect()
	return nil
}

// Close ends the session and releases resources.
func (s *Session) Close() error {
	s.unselect()
	if s.subscription != nil {
		_ = s.subscription.Close()
		s.subscription = nil
	}
	if closer, ok := s.store.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			s.logger.Warn("store close error", "error", err)
		}
	}
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
	s.uidIndex = nil
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
			// Dynamic range (contains "*"). Check each sequence number
			// against the set. Per RFC 9051 §2.3.1.1, ranges containing
			// "*" always include the last message in the mailbox.
			maxIdx := len(s.messages) - 1
			for i := range s.messages {
				seq := uint32(i + 1)
				if ns.Contains(seq) || i == maxIdx {
					indices = append(indices, i)
				}
			}
			return indices
		}
		for _, n := range nums {
			indices = append(indices, int(n)-1)
		}
	case imap.UIDSet:
		uids, ok := ns.Nums()
		if !ok {
			// Dynamic range (contains "*"). Check each message's real UID
			// against the set. Per RFC 9051 §2.3.1.1, ranges containing
			// "*" always include the last message in the mailbox.
			maxIdx := len(s.messages) - 1
			for i, msg := range s.messages {
				uid := imap.UID(msg.UID)
				if ns.Contains(uid) || i == maxIdx {
					indices = append(indices, i)
				}
			}
			return indices
		}
		// Static UIDs: look up in uidIndex map for O(1) resolution.
		for _, u := range uids {
			if idx, ok := s.uidIndex[u]; ok {
				indices = append(indices, idx)
			}
		}
	}
	return indices
}

// buildUIDIndex populates the uidIndex map from the current message list.
func (s *Session) buildUIDIndex() {
	s.uidIndex = make(map[imap.UID]int, len(s.messages))
	for i, m := range s.messages {
		s.uidIndex[imap.UID(m.UID)] = i
	}
}
