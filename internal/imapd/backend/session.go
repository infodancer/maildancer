// Package backend implements the IMAP session using the msgstore interface.
package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/logging"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/imapd/notify"
	"github.com/infodancer/maildancer/internal/smclient"
	"github.com/infodancer/maildancer/msgstore"
	storeerrors "github.com/infodancer/maildancer/msgstore/errors"
)

// keepaliveRPCTimeout bounds a single IDLE-time keepalive RPC. Set short so
// that a hung upstream doesn't keep the goroutine alive past IDLE teardown.
const keepaliveRPCTimeout = 10 * time.Second

// Session implements imapserver.Session backed by the msgstore interface.
type Session struct {
	conn        *imapserver.Conn
	cfg         *config.Config
	store       msgstore.MessageStore
	folderStore msgstore.FolderStore
	smClient    *SessionManagerClient
	smSession   *smclient.Session // recovering session; nil before Login

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

	// mu guards the selected state and subscription against concurrent
	// teardown (#202): on abrupt client disconnect, go-imap's handleIdle
	// returns without waiting for the Idle handler, so Session.Close runs
	// while the Idle goroutine (and its keepalive) is still live. Command
	// paths are serialized by go-imap and never overlap the Idle goroutine,
	// so only Idle-side readers and Close/unselect take the lock. closed is
	// signalled by Close before it touches shared state so Idle can bail.
	mu        sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}

	// Selected state
	selectedMailbox     string
	selectedUIDValidity uint32 // captured at Select for the recovery continuity check
	messages            []msgstore.MessageInfo
	uidIndex            map[imap.UID]int // UID → message index, built on Select
	tracker             *imapserver.MailboxTracker
	sessionTracker      *imapserver.SessionTracker
	readOnly            bool
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
		closed:            make(chan struct{}),
	}
}

// Login authenticates the user via the session-manager service. The
// credential is retained inside the recovering session (this per-connection
// handler process only, zeroed on close) so the session can transparently
// re-login if session-manager restarts (#179, session-recovery-design.md).
func (s *Session) Login(username, password string) error {
	ctx := context.Background()
	smSess := smclient.NewSession(s.smClient, smclient.SessionConfig{
		RecoveryDeadline: s.cfg.Timeouts.RecoveryDeadline(),
	}, s.logger)
	smSess.SetRecoveredHook(s.recoveredHook)
	smSess.SetRecoveryMetric(s.collector.SessionRecovery)

	mailbox, err := smSess.Login(ctx, username, password)
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
	s.smSession = smSess

	smStore := newSessionManagerStore(smSess)
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

// recoveredHook is the post-recovery continuity check
// (session-recovery-design.md): after a transparent re-login, the selected
// folder's UIDVALIDITY must be unchanged or the session cannot resume
// without violating IMAP semantics. It runs against the raw client (no
// recursion into the recovery engine). It can run on the Idle or keepalive
// goroutine, so the selected state is read under the session lock.
func (s *Session) recoveredHook(ctx context.Context, c *smclient.Client, token string) error {
	s.mu.Lock()
	folder := s.selectedMailbox
	wantUV := s.selectedUIDValidity
	s.mu.Unlock()
	if folder == "" {
		return nil
	}
	uv, err := c.UIDValidity(ctx, token, folder)
	if err != nil {
		return err
	}
	if uv != wantUV {
		return fmt.Errorf("uidvalidity changed across recovery: %d -> %d", wantUV, uv)
	}
	return nil
}

// isFatalSessionErr reports errors after which the session cannot continue:
// recovery was refused (credential rejected, continuity check failed) or
// exhausted (deadline). The connection should be dropped so the client
// reconnects and re-authenticates.
func isFatalSessionErr(err error) bool {
	return errors.Is(err, smclient.ErrCredentialRejected) ||
		errors.Is(err, smclient.ErrRecoveryDeadline)
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
	// Snapshot the shared state once: none of it changes during an IDLE
	// except by Close tearing the session down underneath us (#202), and
	// the snapshots keep this goroutine off the fields Close writes.
	s.mu.Lock()
	tracker := s.tracker
	sessionTracker := s.sessionTracker
	sub := s.subscription
	selected := s.selectedMailbox
	folderStore := s.folderStore
	s.mu.Unlock()
	if sessionTracker == nil {
		return nil
	}

	done := make(chan struct{})
	defer close(done)
	if s.keepaliveInterval > 0 && selected != "" && folderStore != nil {
		go s.runIdleKeepalive(done, folderStore, selected)
	}

	// If no Redis subscription, fall back to the standard tracker-only idle.
	if sub == nil {
		return sessionTracker.Idle(w, stop)
	}

	for {
		select {
		case <-s.closed:
			return nil
		case <-stop:
			return sessionTracker.Poll(w, true)
		case msg, ok := <-sub.C:
			if !ok {
				// Channel closed. If the session is being torn down,
				// get out of Close's way; otherwise fall back to the
				// blocking tracker-only idle.
				select {
				case <-s.closed:
					return nil
				default:
				}
				return sessionTracker.Idle(w, stop)
			}
			// Only trigger rescan if the notified folder matches the selected mailbox.
			if !strings.EqualFold(msg.Payload, selected) {
				continue
			}
			newMsgs, err := s.newMessagesSinceLastReport(context.Background(), selected)
			if err != nil {
				// The recovering store already retried transient
				// failures; what comes back is either fatal for the
				// session (drop so the client reconnects cleanly
				// instead of hanging) or folder-level noise.
				if isFatalSessionErr(err) {
					s.logger.Warn("session lost during idle", "error", err)
					return err
				}
				s.logger.Warn("rescan after notification failed", "error", err)
				continue
			}
			if len(newMsgs) > 0 {
				s.mu.Lock()
				if s.sessionTracker != sessionTracker {
					// Torn down (or reselected) while we were listing.
					s.mu.Unlock()
					return nil
				}
				s.messages = append(s.messages, newMsgs...)
				s.buildUIDIndex()
				count := uint32(len(s.messages))
				s.mu.Unlock()
				tracker.QueueNumMessages(count)
				if err := sessionTracker.Poll(w, false); err != nil {
					return err
				}
			}
		}
	}
}

// newMessagesSinceLastReport lists the selected folder and returns messages
// this connection has not yet reported to the client. The diff is computed
// locally against s.messages rather than via the upstream Rescan RPC: that
// RPC diffs against the mail-session process's own cache, and session
// recovery (#179) replaces the process -- the fresh one's baseline absorbs
// mail delivered during the outage, silently dropping it from the diff
// (#201). This connection's message list is the one stable record of what
// the client has been told.
//
// Runs on the Idle goroutine: the known set is captured under the session
// lock, and the listing RPC happens without it.
func (s *Session) newMessagesSinceLastReport(ctx context.Context, folder string) ([]msgstore.MessageInfo, error) {
	s.mu.Lock()
	known := make(map[uint32]struct{}, len(s.messages))
	for _, m := range s.messages {
		known[m.UID] = struct{}{}
	}
	s.mu.Unlock()
	all, err := s.listMessages(ctx, folder)
	if err != nil {
		return nil, err
	}
	newMsgs := make([]msgstore.MessageInfo, 0)
	for _, m := range all {
		if _, ok := known[m.UID]; !ok {
			newMsgs = append(newMsgs, m)
		}
	}
	return newMsgs, nil
}

// runIdleKeepalive periodically issues a cheap RPC against the upstream store
// while an IDLE is active, preventing mail-session's idle interceptor from
// reaping the session. The RPC goes through the recovering session, so it
// doubles as the recovery probe during a session-manager restart (#179):
// transient failures are retried on subsequent ticks, and each tick's
// recovery attempt is bounded by keepaliveRPCTimeout. The loop tears the
// connection down when recovery is refused (fatal) or when failures persist
// past the recovery deadline -- a silent zombie IDLE was the original #126
// symptom.
// The store and folder are passed in as snapshots taken at IDLE start so
// this goroutine never reads fields a concurrent Close writes (#202).
func (s *Session) runIdleKeepalive(done <-chan struct{}, folderStore msgstore.FolderStore, folder string) {
	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()
	var failingSince time.Time
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), keepaliveRPCTimeout)
			_, err := folderStore.UIDValidity(ctx, s.mailbox, folder)
			cancel()
			if err == nil {
				failingSince = time.Time{}
				continue
			}
			s.logger.Warn("idle keepalive failed", "error", err)
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			if isFatalSessionErr(err) || time.Since(failingSince) > s.cfg.Timeouts.RecoveryDeadline() {
				s.logger.Warn("session unrecoverable during idle; closing connection")
				_ = s.conn.NetConn().Close()
				return
			}
		}
	}
}

// Unselect closes the currently selected mailbox without expunging.
func (s *Session) Unselect() error {
	s.unselect()
	return nil
}

// Close ends the session and releases resources. On abrupt client
// disconnect go-imap calls this while the Idle goroutine may still be
// running (#202): the closed signal fires first so Idle can bail, and all
// shared-state teardown happens under the session lock.
func (s *Session) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	s.mu.Lock()
	s.unselectLocked()
	sub := s.subscription
	s.subscription = nil
	store := s.store
	s.mu.Unlock()
	if sub != nil {
		_ = sub.Close()
	}
	if closer, ok := store.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			s.logger.Warn("store close error", "error", err)
		}
	}
	s.recordTLSConnection()
	s.collector.ConnectionClosed()
	return nil
}

// recordTLSConnection counts the connection's TLS session, if it had one,
// exactly once (#207). Neither TLS path offers a hook of its own: implicit TLS
// hands go-imap an already-wrapped conn, and STARTTLS is performed inside
// go-imap. Session close is the one place both are observable exactly once --
// go-imap creates the session before the greeting (so before the implicit
// handshake has run) and keeps the same session across a STARTTLS upgrade,
// which rules out counting at session creation. Conn.NetConn() returns the
// current transport, which go-imap swaps for the *tls.Conn on upgrade.
//
// Counting at session end costs nothing: handler metrics only reach the
// dispatcher over the report pipe at process exit anyway (#188), so an earlier
// count would not surface the number any sooner.
//
// HandshakeComplete is required, not merely the presence of a *tls.Conn:
// implicit TLS wraps the connection before the handshake runs, so counting on
// the wrapper alone would credit failed handshakes as established TLS
// sessions -- the failure mode of #199.
func (s *Session) recordTLSConnection() {
	if s.conn == nil {
		return // unit-test sessions are built without a transport
	}
	tc, ok := s.conn.NetConn().(*tls.Conn)
	if ok && tc.ConnectionState().HandshakeComplete {
		s.collector.TLSConnectionEstablished()
	}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unselectLocked()
}

func (s *Session) unselectLocked() {
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
