package smclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Session recovery (session-recovery-design.md, issue #179).
//
// A Session wraps a Client with the credential retained for the lifetime of
// one client connection, and transparently re-establishes the session when
// the session-manager restarts (its token map is in-memory, so every token
// dies with it). Reads are retried after recovery; writes are never replayed
// (at-most-once) -- recovery still runs so the session is healthy for the
// next command, but the in-flight write returns its failure to the caller.

// ErrCredentialRejected reports that re-login during recovery was refused:
// the retained credential is no longer valid (password changed, account
// disabled). Recovery cannot succeed; the connection must be dropped so the
// client re-authenticates.
var ErrCredentialRejected = errors.New("session recovery: credential rejected")

// ErrRecoveryDeadline reports that the session-manager did not come back
// within the recovery deadline.
var ErrRecoveryDeadline = errors.New("session recovery: deadline exceeded")

// ErrNotLoggedIn reports an RPC attempted before Login.
var ErrNotLoggedIn = errors.New("smclient: session not logged in")

const (
	backoffInitial = 250 * time.Millisecond
	backoffMax     = 15 * time.Second
	// DefaultRecoveryDeadline bounds how long a session keeps trying to
	// recover before declaring itself dead (config: session_recovery_deadline).
	DefaultRecoveryDeadline = 2 * time.Minute
)

// SessionConfig tunes recovery behavior.
type SessionConfig struct {
	// RecoveryDeadline bounds the total time spent recovering a single
	// failed RPC. Zero means DefaultRecoveryDeadline.
	RecoveryDeadline time.Duration
}

// RecoveredHook runs after a successful re-login, before the failed RPC is
// retried. It receives the raw client and the fresh token so it can perform
// continuity checks (e.g. imapd's UIDVALIDITY comparison) without recursing
// into the recovery engine. Returning an error aborts the recovery: the
// session is declared dead and the connection should be dropped.
type RecoveredHook func(ctx context.Context, c *Client, token string) error

// Session is a recovering, credential-retaining session with the
// session-manager. It is safe for concurrent use.
type Session struct {
	client *Client
	cfg    SessionConfig
	logger *slog.Logger

	mu       sync.Mutex
	token    string
	username string
	cred     []byte // retained credential; zeroed on Close/fatal
	clientIP string // peer address, replayed on recovery re-login
	mailbox  string

	recoverMu sync.Mutex // single-flight recovery

	onRecovered RecoveredHook
	onRecovery  func(result string) // metrics: "ok" | "auth_failed" | "deadline"
}

// NewSession wraps client in a recovering session.
func NewSession(client *Client, cfg SessionConfig, logger *slog.Logger) *Session {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.RecoveryDeadline <= 0 {
		cfg.RecoveryDeadline = DefaultRecoveryDeadline
	}
	return &Session{client: client, cfg: cfg, logger: logger}
}

// SetRecoveredHook installs the post-recovery continuity hook. Call before
// concurrent use.
func (s *Session) SetRecoveredHook(h RecoveredHook) { s.onRecovered = h }

// SetRecoveryMetric installs the recovery-outcome counter hook. Call before
// concurrent use.
func (s *Session) SetRecoveryMetric(f func(result string)) { s.onRecovery = f }

// Login authenticates and retains the presented credential for the lifetime
// of this session, enabling recovery. The credential lives only in this
// process (a per-connection protocol handler) and is zeroed on Close.
func (s *Session) Login(ctx context.Context, username, password, clientIP string) (mailbox string, err error) {
	token, mbox, err := s.client.Login(ctx, username, password, clientIP)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.token = token
	s.username = username
	s.cred = []byte(password)
	s.mailbox = mbox
	// Retained alongside the credential so a transparent re-login is keyed to
	// the same peer as the original: a recovery that arrived with no client IP
	// would silently bypass rate limiting (#206).
	s.clientIP = clientIP
	s.mu.Unlock()
	return mbox, nil
}

// Logout releases the session (best-effort; no recovery) and zeros the
// retained credential.
func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	token := s.token
	s.mu.Unlock()
	defer s.Close()
	if token == "" {
		return nil
	}
	return s.client.Logout(ctx, token)
}

// Close zeros the retained credential. It does not close the underlying
// Client (whose lifecycle belongs to the caller). Safe to call repeatedly.
func (s *Session) Close() {
	s.mu.Lock()
	for i := range s.cred {
		s.cred[i] = 0
	}
	s.cred = nil
	s.token = ""
	s.mu.Unlock()
}

// Mailbox returns the authenticated mailbox identifier from Login.
func (s *Session) Mailbox() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mailbox
}

// currentToken returns the live token, or "" when not logged in.
func (s *Session) currentToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// recoverable reports whether err is in the recovery trigger set:
// Unavailable (manager down or restarting) or Unauthenticated on a data RPC
// (manager restarted; token map empty).
func recoverable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.Unauthenticated:
		return true
	default:
		return false
	}
}

// recover re-establishes the session after failedToken died. Single-flight:
// concurrent callers serialize, and a caller whose token is already stale
// (someone else recovered first) returns immediately. A nil return means the
// session holds a fresh valid token. ErrCredentialRejected means the retained
// credential no longer works -- fatal. Any other error is transient (manager
// still down).
func (s *Session) recover(ctx context.Context, failedToken string) error {
	s.recoverMu.Lock()
	defer s.recoverMu.Unlock()

	s.mu.Lock()
	current := s.token
	username := s.username
	cred := string(s.cred)
	clientIP := s.clientIP
	s.mu.Unlock()

	if current != failedToken {
		return nil // another goroutine already recovered
	}
	if cred == "" {
		return ErrNotLoggedIn
	}

	token, mbox, err := s.client.Login(ctx, username, cred, clientIP)
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			// The manager is up and refused the credential: password
			// changed or account disabled. Not retryable.
			if s.onRecovery != nil {
				s.onRecovery("auth_failed")
			}
			s.Close() // zero the now-useless credential
			return fmt.Errorf("%w: %v", ErrCredentialRejected, err)
		}
		return err // transient; caller keeps backing off
	}

	if s.onRecovered != nil {
		if herr := s.onRecovered(ctx, s.client, token); herr != nil {
			// Continuity check failed (e.g. UIDVALIDITY changed):
			// transparent resumption would be incorrect. Best-effort
			// logout of the fresh session, then declare fatal.
			_ = s.client.Logout(ctx, token)
			if s.onRecovery != nil {
				s.onRecovery("auth_failed")
			}
			return fmt.Errorf("%w: continuity check: %v", ErrCredentialRejected, herr)
		}
	}

	s.mu.Lock()
	s.token = token
	s.mailbox = mbox
	s.mu.Unlock()

	if s.onRecovery != nil {
		s.onRecovery("ok")
	}
	s.logger.Info("session recovered after session-manager restart")
	return nil
}

// doRead runs an idempotent RPC with transparent recovery: on a trigger-set
// error it recovers and retries until success, a fatal error, or the
// recovery deadline.
func (s *Session) doRead(ctx context.Context, fn func(ctx context.Context, token string) error) error {
	token := s.currentToken()
	if token == "" {
		return ErrNotLoggedIn
	}

	err := fn(ctx, token)
	if err == nil || !recoverable(err) {
		return err
	}

	deadline := time.NewTimer(s.cfg.RecoveryDeadline)
	defer deadline.Stop()
	backoff := backoffInitial

	for {
		if status.Code(err) == codes.Unauthenticated {
			rerr := s.recover(ctx, token)
			switch {
			case rerr == nil:
				// fresh token; retry immediately
			case errors.Is(rerr, ErrCredentialRejected), errors.Is(rerr, ErrNotLoggedIn):
				return rerr
			default:
				// manager still down; fall through to backoff
			}
		}

		token = s.currentToken()
		if token != "" {
			err = fn(ctx, token)
			if err == nil || !recoverable(err) {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if s.onRecovery != nil {
				s.onRecovery("deadline")
			}
			return fmt.Errorf("%w: %v", ErrRecoveryDeadline, err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// doWrite runs a non-idempotent RPC with at-most-once semantics: the RPC is
// never replayed. On a trigger-set failure, recovery still runs (bounded by
// the deadline) so the session is healthy for the caller's next command, but
// the original error is returned regardless.
func (s *Session) doWrite(ctx context.Context, fn func(ctx context.Context, token string) error) error {
	token := s.currentToken()
	if token == "" {
		return ErrNotLoggedIn
	}

	err := fn(ctx, token)
	if err == nil || !recoverable(err) {
		return err
	}

	// Recover for the benefit of subsequent commands; never retry the write.
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RecoveryDeadline)
	defer cancel()
	backoff := backoffInitial
	for {
		rerr := s.recover(rctx, token)
		if rerr == nil || errors.Is(rerr, ErrCredentialRejected) || errors.Is(rerr, ErrNotLoggedIn) {
			break
		}
		select {
		case <-rctx.Done():
			if s.onRecovery != nil {
				s.onRecovery("deadline")
			}
			return err
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
	return err
}

// --- Recovering RPC surface (reads retry; writes are at-most-once) ---

// ListMessages returns message metadata for all messages in the given folder.
func (s *Session) ListMessages(ctx context.Context, folder string) (msgs []*pb.MessageInfo, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		msgs, err = s.client.ListMessages(ctx, token, folder)
		return err
	})
	return msgs, err
}

// StatMailbox returns the message count and total byte size for a folder.
func (s *Session) StatMailbox(ctx context.Context, folder string) (count int32, size int64, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		count, size, err = s.client.StatMailbox(ctx, token, folder)
		return err
	})
	return count, size, err
}

// FetchMessage retrieves a message by UID.
func (s *Session) FetchMessage(ctx context.Context, folder string, uid uint32) (rc io.ReadCloser, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		rc, err = s.client.FetchMessage(ctx, token, folder, uid)
		return err
	})
	return rc, err
}

// SearchContent evaluates content predicates server-side.
func (s *Session) SearchContent(ctx context.Context, folder string, uids []uint32, bodyTerms, textTerms []string, needHeaders bool) (results []*pb.SearchContentResult, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		results, err = s.client.SearchContent(ctx, token, folder, uids, bodyTerms, textTerms, needHeaders)
		return err
	})
	return results, err
}

// UIDValidity returns the UIDVALIDITY for a folder.
func (s *Session) UIDValidity(ctx context.Context, folder string) (uv uint32, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		uv, err = s.client.UIDValidity(ctx, token, folder)
		return err
	})
	return uv, err
}

// UIDNext returns the next UID that will be assigned in a folder.
func (s *Session) UIDNext(ctx context.Context, folder string) (un uint32, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		un, err = s.client.UIDNext(ctx, token, folder)
		return err
	})
	return un, err
}

// RescanFolder re-reads a folder and returns only new messages since the
// last List or Rescan.
func (s *Session) RescanFolder(ctx context.Context, folder string) (msgs []*pb.MessageInfo, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		msgs, err = s.client.RescanFolder(ctx, token, folder)
		return err
	})
	return msgs, err
}

// ListFolders returns all folder names.
func (s *Session) ListFolders(ctx context.Context) (folders []string, err error) {
	err = s.doRead(ctx, func(ctx context.Context, token string) error {
		folders, err = s.client.ListFolders(ctx, token)
		return err
	})
	return folders, err
}

// SetFlags replaces the complete flag set on a message. At-most-once.
func (s *Session) SetFlags(ctx context.Context, folder string, uid uint32, flags []string) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.SetFlags(ctx, token, folder, uid, flags)
	})
}

// DeleteMessage marks a message \Deleted (IMAP-style). At-most-once.
func (s *Session) DeleteMessage(ctx context.Context, folder string, uid uint32) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.DeleteMessage(ctx, token, folder, uid)
	})
}

// Delete marks a message for POP3-style deletion. At-most-once.
func (s *Session) Delete(ctx context.Context, uid uint32) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.Delete(ctx, token, uid)
	})
}

// ExpungeMailbox permanently removes all deleted messages in a folder.
// At-most-once.
func (s *Session) ExpungeMailbox(ctx context.Context, folder string) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.ExpungeMailbox(ctx, token, folder)
	})
}

// CopyMessage copies a message between folders. At-most-once.
func (s *Session) CopyMessage(ctx context.Context, srcFolder string, uid uint32, destFolder string) (newUID uint32, err error) {
	err = s.doWrite(ctx, func(ctx context.Context, token string) error {
		newUID, err = s.client.CopyMessage(ctx, token, srcFolder, uid, destFolder)
		return err
	})
	return newUID, err
}

// MoveMessage atomically moves a message between folders. At-most-once.
func (s *Session) MoveMessage(ctx context.Context, srcFolder string, uid uint32, destFolder string) (newUID uint32, err error) {
	err = s.doWrite(ctx, func(ctx context.Context, token string) error {
		newUID, err = s.client.MoveMessage(ctx, token, srcFolder, uid, destFolder)
		return err
	})
	return newUID, err
}

// AppendMessage stores a message in a folder. At-most-once.
func (s *Session) AppendMessage(ctx context.Context, folder string, r io.Reader, flags []string, date time.Time) (uid uint32, err error) {
	err = s.doWrite(ctx, func(ctx context.Context, token string) error {
		uid, err = s.client.AppendMessage(ctx, token, folder, r, flags, date)
		return err
	})
	return uid, err
}

// CreateFolder creates a new folder. At-most-once.
func (s *Session) CreateFolder(ctx context.Context, name string) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.CreateFolder(ctx, token, name)
	})
}

// DeleteFolder removes a folder. At-most-once.
func (s *Session) DeleteFolder(ctx context.Context, name string) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.DeleteFolder(ctx, token, name)
	})
}

// RenameFolder renames a folder. At-most-once.
func (s *Session) RenameFolder(ctx context.Context, oldName, newName string) error {
	return s.doWrite(ctx, func(ctx context.Context, token string) error {
		return s.client.RenameFolder(ctx, token, oldName, newName)
	})
}
