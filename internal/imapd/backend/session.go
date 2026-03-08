// Package backend implements the IMAP session using the msgstore interface.
package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/logging"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/mail-session/client"
	"github.com/infodancer/maildancer/msgstore"
	storeerrors "github.com/infodancer/maildancer/msgstore/errors"
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

	// Spam learning (nil when disabled)
	learner *spamLearner

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
	var learner *spamLearner
	if cfg.Rspamd.Controller != "" {
		learner = newSpamLearner(cfg.Rspamd.Controller, "")
	}

	return &Session{
		conn:        conn,
		cfg:         cfg,
		authRouter:  authRouter,
		store:       store,
		folderStore: folderStore,
		learner:     learner,
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

	if s.cfg.MailSessionCmd != "" && s.cfg.MailSessionMode == "grpc" {
		gs, spawnErr := s.spawnGrpcMailSession(username)
		if spawnErr != nil {
			s.logger.Error("failed to spawn grpc mail-session", "username", username, "error", spawnErr)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Internal server error",
			}
		}
		s.store = gs
		s.folderStore = gs
	} else if s.cfg.MailSessionCmd != "" {
		subprocStore, spawnErr := s.spawnMailSession(username)
		if spawnErr != nil {
			s.logger.Error("failed to spawn mail-session", "username", username, "error", spawnErr)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Internal server error",
			}
		}
		s.store = subprocStore
		s.folderStore = subprocStore
	} else if result.Domain != nil && result.Domain.MessageStore != nil {
		s.store = result.Domain.MessageStore
		s.folderStore, _ = result.Domain.MessageStore.(msgstore.FolderStore)
	}

	// Ensure default folders exist (idempotent).
	if s.folderStore != nil {
		s.ensureDefaultFolders()
	}

	s.collector.AuthAttempt(s.userDomain, true)
	s.logger.Info("login success", "username", username)
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
	if closer, ok := s.store.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			s.logger.Warn("store close error", "error", err)
		}
	}
	s.collector.ConnectionClosed()
	return nil
}

// spawnMailSession looks up the domain config for username, then starts a
// mail-session subprocess with the appropriate uid/gid/basepath and returns a
// SubprocessStore wired to its stdin/stdout.
func (s *Session) spawnMailSession(username string) (*SubprocessStore, error) {
	localpart, domainName, ok := strings.Cut(username, "@")
	if !ok {
		return nil, fmt.Errorf("invalid username %q: missing @domain", username)
	}

	uid, gid, basePath, storeType, maxMsgSize, err := s.lookupMailSessionParams(localpart, domainName)
	if err != nil {
		return nil, err
	}

	args := []string{"--type", storeType, "--basepath", basePath, "--user", username}
	if maxMsgSize > 0 {
		args = append(args, "--max-message-size", fmt.Sprintf("%d", maxMsgSize))
	}
	if s.cfg.Rspamd.Controller != "" {
		args = append(args, "--rspamd", s.cfg.Rspamd.Controller)
		junk := s.cfg.Rspamd.JunkFolder
		if junk == "" {
			junk = "Junk"
		}
		args = append(args, "--junk-folder", junk)
	}
	cmd := exec.Command(s.cfg.MailSessionCmd, args...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}

	// ── Encryption seam: key pipe (fd 3 in mail-session) ─────────────────────
	// mail-session reads exactly 32 bytes from fd 3 before entering its command
	// loop. NewSubprocessStore starts the process and immediately sends MAILBOX,
	// so the key write runs in a goroutine to avoid a deadlock: mail-session
	// blocks reading fd 3 while NewSubprocessStore waits for the MAILBOX reply.
	// Stub: zeroed bytes are written; real key derivation (auth.DeriveKeyPair)
	// is deferred to a future PR.
	// See: infodancer/infodancer/docs/encryption-design.md
	// ─────────────────────────────────────────────────────────────────────────
	keyPipeR, keyPipeW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("key pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{keyPipeR} // fd 3: read-only session key

	go func() {
		defer keyPipeW.Close()
		// Stub: write a zeroed key envelope so mail-session can proceed.
		// The envelope format is versioned JSON so future fields (algorithm,
		// key_id, keyring) can be added without a breaking protocol change.
		// Real key derivation (auth.DeriveKeyPair) is deferred.
		_ = json.NewEncoder(keyPipeW).Encode(struct {
			Version int    `json:"version"`
			Key     []byte `json:"key"`
		}{Version: 1, Key: make([]byte, 32)})
	}()

	store, err := NewSubprocessStore(cmd, s.mailbox)
	_ = keyPipeR.Close() // child owns fd 3; release parent's copy
	return store, err
}

// spawnGrpcMailSession starts mail-session in daemon mode with a gRPC socket,
// waits for the READY signal, dials gRPC, and returns a grpcStore that manages
// the subprocess lifecycle.
func (s *Session) spawnGrpcMailSession(username string) (*grpcStore, error) {
	localpart, domainName, ok := strings.Cut(username, "@")
	if !ok {
		return nil, fmt.Errorf("invalid username %q: missing @domain", username)
	}

	uid, gid, basePath, storeType, maxMsgSize, err := s.lookupMailSessionParams(localpart, domainName)
	if err != nil {
		return nil, err
	}

	// Create temp directory for the unix domain socket.
	socketDir, err := os.MkdirTemp("", "imapd-session-*")
	if err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	socketPath := filepath.Join(socketDir, "session.sock")

	args := []string{
		"--mode", "daemon",
		"--socket", socketPath,
		"--type", storeType,
		"--basepath", basePath,
		"--user", username,
	}
	if maxMsgSize > 0 {
		args = append(args, "--max-message-size", fmt.Sprintf("%d", maxMsgSize))
	}
	if s.cfg.Rspamd.Controller != "" {
		args = append(args, "--rspamd", s.cfg.Rspamd.Controller)
		junk := s.cfg.Rspamd.JunkFolder
		if junk == "" {
			junk = "Junk"
		}
		args = append(args, "--junk-folder", junk)
	}
	cmd := exec.Command(s.cfg.MailSessionCmd, args...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}

	// Key pipe (fd 3) — same as pipe mode.
	keyPipeR, keyPipeW, err := os.Pipe()
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("key pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{keyPipeR}

	go func() {
		defer func() { _ = keyPipeW.Close() }()
		_ = json.NewEncoder(keyPipeW).Encode(struct {
			Version int    `json:"version"`
			Key     []byte `json:"key"`
		}{Version: 1, Key: make([]byte, 32)})
	}()

	// Capture stdout to read the READY signal.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = keyPipeR.Close()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = keyPipeR.Close()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("start mail-session: %w", err)
	}
	_ = keyPipeR.Close()

	// Wait for READY signal on stdout.
	buf := make([]byte, 64)
	n, err := stdout.Read(buf)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("waiting for READY: %w", err)
	}
	if !strings.Contains(string(buf[:n]), "READY") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("unexpected startup output: %q", string(buf[:n]))
	}

	// Dial the gRPC socket.
	c, err := client.Dial(socketPath)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("dial grpc: %w", err)
	}

	return &grpcStore{
		Client:    c,
		cmd:       cmd,
		socketDir: socketDir,
	}, nil
}

// lookupMailSessionParams reads the per-domain config and passwd file to obtain
// the uid, gid, basePath, and store type for spawning mail-session.
// Mirrors the logic in pop3d's lookupCredentials.
func (s *Session) lookupMailSessionParams(localpart, domainName string) (uid, gid uint32, basePath, storeType string, maxMsgSize int64, err error) {
	domainDir := filepath.Join(s.cfg.DomainsPath, domainName)

	cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		return 0, 0, "", "", 0, fmt.Errorf("load domain config for %q: %w", domainName, err)
	}

	gid = cfg.Gid

	credBackend := cfg.Auth.CredentialBackend
	if credBackend == "" {
		credBackend = "passwd"
	}
	passwdPath := credBackend
	if !filepath.IsAbs(passwdPath) {
		passwdPath = filepath.Join(domainDir, passwdPath)
	}

	uid, err = passwd.LookupUID(passwdPath, localpart)
	if err != nil {
		return 0, 0, "", "", 0, fmt.Errorf("lookup uid for %q in %q: %w", localpart, passwdPath, err)
	}

	base := cfg.MsgStore.BasePath
	if base == "" {
		base = "users"
	}
	if !filepath.IsAbs(base) {
		base = filepath.Join(domainDir, base)
	}

	storeType = cfg.MsgStore.Type
	if storeType == "" {
		storeType = "maildir"
	}

	return uid, gid, base, storeType, cfg.MaxMessageSize, nil
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
