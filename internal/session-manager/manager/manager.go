// Package manager handles mail-session process lifecycle: spawning, session
// reuse (ref-counting), idle reaping, and credential lookup.
package manager

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/credentials"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// sessionEntry tracks a single per-user mail-session process.
type sessionEntry struct {
	username  string
	mailbox   string
	conn      *grpc.ClientConn
	mailboxCl pb.MailboxServiceClient
	folderCl  pb.FolderServiceClient
	watchCl   pb.WatchServiceClient
	cmd       *exec.Cmd
	socketDir string
	refCount  int
	idleTimer *time.Timer
	waited    bool // true after cmd.Wait() has been called
}

// Manager handles mail-session lifecycle.
type Manager struct {
	cfg            *config.Config
	authRouter     *domain.AuthRouter
	domainProvider domain.DomainProvider
	metrics        metrics.Collector

	mu sync.Mutex
	// byToken maps session tokens to session entries.
	byToken map[string]*sessionEntry
	// byUser maps username to session entry for reuse.
	byUser map[string]*sessionEntry

	// Test hooks (unexported, nil in production).
	authFn  func(ctx context.Context, username, password string) (mailbox string, err error)
	spawnFn func(username, mailbox string) (*sessionEntry, error)
}

// New creates a new Manager.
func New(cfg *config.Config, authRouter *domain.AuthRouter, dp domain.DomainProvider, mc metrics.Collector) *Manager {
	return &Manager{
		cfg:            cfg,
		authRouter:     authRouter,
		domainProvider: dp,
		metrics:        mc,
		byToken:        make(map[string]*sessionEntry),
		byUser:         make(map[string]*sessionEntry),
	}
}

// LoginResult holds the results of a successful Login call.
type LoginResult struct {
	Token           string
	Mailbox         string
	Extension       string
	MaxSendsPerHour int
}

// Login authenticates a user, spawns (or reuses) a mail-session, and returns
// a LoginResult with session token, mailbox, subaddress extension, and rate limit.
func (m *Manager) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	var mailbox, extension string
	var maxSendsPerHour int
	var err error

	if m.authFn != nil {
		mailbox, err = m.authFn(ctx, username, password)
	} else {
		var result *domain.AuthResult
		result, err = m.authRouter.AuthenticateWithDomain(ctx, username, password)
		if err == nil {
			mailbox = result.Session.User.Mailbox
			extension = result.Extension
			if result.Domain != nil {
				maxSendsPerHour = result.Domain.Limits.MaxSendsPerHour
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	mkResult := func(token string) *LoginResult {
		return &LoginResult{
			Token:           token,
			Mailbox:         mailbox,
			Extension:       extension,
			MaxSendsPerHour: maxSendsPerHour,
		}
	}

	// Fast path: reuse existing session under short lock.
	m.mu.Lock()
	if entry, ok := m.byUser[username]; ok {
		if !m.isAliveLocked(entry) {
			// Subprocess died; clean up stale entry and fall through to spawn.
			slog.Warn("stale session detected, removing",
				"username", username)
			m.removeEntryLocked(entry)
		} else {
			if entry.idleTimer != nil {
				entry.idleTimer.Stop()
				entry.idleTimer = nil
			}
			entry.refCount++
			tok := m.generateTokenLocked(entry)
			m.mu.Unlock()
			slog.Debug("session reused",
				"username", username,
				"ref_count", entry.refCount)
			return mkResult(tok), nil
		}
	}
	m.mu.Unlock()

	// Slow path: spawn outside the lock to avoid blocking other operations.
	var entry *sessionEntry
	if m.spawnFn != nil {
		entry, err = m.spawnFn(username, mailbox)
	} else {
		entry, err = m.spawnSession(username, mailbox)
	}
	if err != nil {
		return nil, err
	}

	// Re-acquire lock and check for race (another goroutine may have
	// spawned a session for the same user while we were spawning).
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.byUser[username]; ok {
		// Another goroutine won the race. Discard ours, reuse theirs.
		m.killEntry(entry)
		if existing.idleTimer != nil {
			existing.idleTimer.Stop()
			existing.idleTimer = nil
		}
		existing.refCount++
		tok := m.generateTokenLocked(existing)
		slog.Debug("session reused (race resolved)",
			"username", username,
			"ref_count", existing.refCount)
		return mkResult(tok), nil
	}

	m.byUser[username] = entry
	tok := m.generateTokenLocked(entry)

	var pid int
	if entry.cmd != nil && entry.cmd.Process != nil {
		pid = entry.cmd.Process.Pid
	}
	slog.Info("session created", "username", username, "pid", pid)
	m.metrics.SessionCreated()

	go m.monitorProcess(entry)

	return mkResult(tok), nil
}

// Logout decrements the ref count for a session token. When the last
// reference is released, an idle timer starts.
func (m *Manager) Logout(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byToken[token]
	if !ok {
		return fmt.Errorf("unknown session token")
	}
	delete(m.byToken, token)

	entry.refCount--
	m.metrics.SessionClosed()
	if entry.refCount <= 0 {
		entry.idleTimer = time.AfterFunc(m.cfg.IdleTimeout, func() {
			m.reapSession(entry)
		})
		slog.Debug("session idle timer started",
			"username", entry.username,
			"timeout", m.cfg.IdleTimeout)
	}

	return nil
}

// SessionForToken returns the gRPC service clients for a session token.
// Returns an error if the token is not valid.
func (m *Manager) SessionForToken(token string) (pb.MailboxServiceClient, pb.FolderServiceClient, pb.WatchServiceClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byToken[token]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown session token")
	}
	return entry.mailboxCl, entry.folderCl, entry.watchCl, nil
}

// DeliverySession spawns a oneshot mail-session for delivery to the given
// recipient and returns a DeliveryServiceClient. The caller must call the
// returned cleanup function when done.
func (m *Manager) DeliverySession(ctx context.Context, recipient string) (pb.DeliveryServiceClient, func(), error) {
	localpart, domainName, ok := strings.Cut(recipient, "@")
	if !ok {
		return nil, nil, fmt.Errorf("invalid recipient %q: missing @domain", recipient)
	}

	creds, err := credentials.Lookup(m.cfg.DomainsPath, m.cfg.DomainsDataPath, localpart, domainName)
	if err != nil {
		return nil, nil, fmt.Errorf("credential lookup for %q: %w", recipient, err)
	}

	socketDir, err := os.MkdirTemp("", "session-mgr-deliver-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create socket dir: %w", err)
	}

	// The child process runs as a different uid/gid via SysProcAttr; it needs
	// write access to the socket directory to create the unix socket.
	if err := os.Chown(socketDir, int(creds.UID), int(creds.GID)); err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, nil, fmt.Errorf("chown socket dir: %w", err)
	}

	socketPath := filepath.Join(socketDir, "session.sock")

	args := []string{
		"--mode=oneshot",
		"--socket=" + socketPath,
		"--mailbox=" + recipient,
		"--type=" + creds.StoreType,
		"--basepath=" + creds.BasePath,
		"--domains-path=" + m.cfg.DomainsPath,
	}
	if m.cfg.DomainsDataPath != "" {
		args = append(args, "--domains-data-path="+m.cfg.DomainsDataPath)
	}

	cmd := exec.CommandContext(ctx, m.cfg.MailSessionCmd, args...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: creds.UID,
			Gid: creds.GID,
		},
	}

	if err := m.startAndWaitReady(cmd); err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, nil, fmt.Errorf("start oneshot mail-session: %w", err)
	}

	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
		return nil, nil, fmt.Errorf("dial oneshot grpc: %w", err)
	}

	deliveryCl := pb.NewDeliveryServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
	}

	return deliveryCl, cleanup, nil
}

// Close terminates all active sessions.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.byUser {
		if entry.idleTimer != nil {
			entry.idleTimer.Stop()
		}
		m.killEntry(entry)
	}
	m.byToken = make(map[string]*sessionEntry)
	m.byUser = make(map[string]*sessionEntry)
}

// spawnSession starts a new mail-session daemon process for the given user.
func (m *Manager) spawnSession(username, mailbox string) (*sessionEntry, error) {
	localpart, domainName, ok := strings.Cut(username, "@")
	if !ok {
		return nil, fmt.Errorf("invalid username %q: missing @domain", username)
	}

	creds, err := credentials.Lookup(m.cfg.DomainsPath, m.cfg.DomainsDataPath, localpart, domainName)
	if err != nil {
		return nil, fmt.Errorf("credential lookup: %w", err)
	}

	socketDir, err := os.MkdirTemp("", "session-mgr-*")
	if err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	// The child process runs as a different uid/gid via SysProcAttr; it needs
	// write access to the socket directory to create the unix socket.
	if err := os.Chown(socketDir, int(creds.UID), int(creds.GID)); err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("chown socket dir: %w", err)
	}

	socketPath := filepath.Join(socketDir, "session.sock")

	args := []string{
		"--mode=daemon",
		"--socket=" + socketPath,
		"--mailbox=" + mailbox,
		"--type=" + creds.StoreType,
		"--basepath=" + creds.BasePath,
	}
	if m.cfg.DomainsPath != "" {
		args = append(args, "--domains-path="+m.cfg.DomainsPath)
	}
	if m.cfg.DomainsDataPath != "" {
		args = append(args, "--domains-data-path="+m.cfg.DomainsDataPath)
	}

	cmd := exec.Command(m.cfg.MailSessionCmd, args...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: creds.UID,
			Gid: creds.GID,
		},
	}

	if err := m.startAndWaitReady(cmd); err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("start mail-session: %w", err)
	}

	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("dial grpc: %w", err)
	}

	return &sessionEntry{
		username:  username,
		mailbox:   mailbox,
		conn:      conn,
		mailboxCl: pb.NewMailboxServiceClient(conn),
		folderCl:  pb.NewFolderServiceClient(conn),
		watchCl:   pb.NewWatchServiceClient(conn),
		cmd:       cmd,
		socketDir: socketDir,
		refCount:  1,
	}, nil
}

// startAndWaitReady starts the command and waits for "READY" on stdout.
func (m *Manager) startAndWaitReady(cmd *exec.Cmd) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	readyCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				readyCh <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			readyCh <- fmt.Errorf("reading stdout: %w", err)
		} else {
			readyCh <- fmt.Errorf("mail-session exited without READY signal")
		}
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
		return nil
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("timed out waiting for READY signal")
	}
}

// generateTokenLocked creates a random session token and registers it.
// Must be called with m.mu held.
func (m *Manager) generateTokenLocked(entry *sessionEntry) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; if it does, panic is appropriate.
		panic("crypto/rand failed: " + err.Error())
	}
	token := hex.EncodeToString(b)
	m.byToken[token] = entry
	return token
}

// isAliveLocked checks whether the subprocess backing a session entry is still
// running. Must be called with m.mu held.
func (m *Manager) isAliveLocked(entry *sessionEntry) bool {
	if entry.cmd == nil {
		// No subprocess (test stub or in-process mock) — assume alive.
		return true
	}
	if entry.cmd.Process == nil {
		return false
	}
	// Signal 0 checks process existence without sending a real signal.
	return entry.cmd.Process.Signal(syscall.Signal(0)) == nil
}

// removeEntryLocked removes a session entry from all maps and kills it.
// Must be called with m.mu held.
func (m *Manager) removeEntryLocked(entry *sessionEntry) {
	if entry.idleTimer != nil {
		entry.idleTimer.Stop()
		entry.idleTimer = nil
	}
	delete(m.byUser, entry.username)
	for tok, e := range m.byToken {
		if e == entry {
			delete(m.byToken, tok)
		}
	}
	m.killEntry(entry)
}

// monitorProcess waits for a mail-session subprocess to exit and cleans up its
// registry entry. This catches cases where the subprocess exits on its own
// (e.g., idle timeout) without waiting for the manager's reap timer.
func (m *Manager) monitorProcess(entry *sessionEntry) {
	if entry.cmd == nil {
		return
	}
	// cmd.Wait() blocks until the process exits. Ignore the error — the
	// process may exit cleanly (idle timeout) or be killed by reapSession.
	_ = entry.cmd.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	entry.waited = true

	// Only clean up if this entry is still in the registry. If reapSession
	// or Close already removed it, there's nothing to do.
	if existing, ok := m.byUser[entry.username]; ok && existing == entry {
		slog.Info("mail-session process exited, cleaning up",
			"username", entry.username)
		if entry.idleTimer != nil {
			entry.idleTimer.Stop()
			entry.idleTimer = nil
		}
		delete(m.byUser, entry.username)
		for tok, e := range m.byToken {
			if e == entry {
				delete(m.byToken, tok)
			}
		}
		// Process already exited; just clean up resources.
		if entry.conn != nil {
			_ = entry.conn.Close()
		}
		if entry.socketDir != "" {
			_ = os.RemoveAll(entry.socketDir)
		}
	}
}

// reapSession terminates a mail-session that has been idle.
func (m *Manager) reapSession(entry *sessionEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: if refCount went back up, don't reap.
	if entry.refCount > 0 {
		return
	}

	var pid int
	if entry.cmd != nil && entry.cmd.Process != nil {
		pid = entry.cmd.Process.Pid
	}
	slog.Info("reaping idle session", "username", entry.username, "pid", pid)
	m.metrics.SessionReaped()

	delete(m.byUser, entry.username)

	// Remove all tokens pointing to this entry.
	for tok, e := range m.byToken {
		if e == entry {
			delete(m.byToken, tok)
		}
	}

	m.killEntry(entry)
}

// killEntry terminates the mail-session process and cleans up resources.
// Safe to call even if the process has already exited and been waited on.
func (m *Manager) killEntry(entry *sessionEntry) {
	if entry.conn != nil {
		_ = entry.conn.Close()
	}
	if entry.cmd != nil && entry.cmd.Process != nil && !entry.waited {
		_ = entry.cmd.Process.Signal(syscall.SIGTERM)
		_ = entry.cmd.Wait()
		entry.waited = true
	}
	if entry.socketDir != "" {
		_ = os.RemoveAll(entry.socketDir)
	}
}

// AuthRouter returns the auth router for use outside the manager.
func (m *Manager) AuthRouter() *domain.AuthRouter {
	return m.authRouter
}

// ValidateRecipient checks whether a recipient address is deliverable.
// Returns whether the domain is local, whether the user exists, and
// the per-domain rejection policy.
func (m *Manager) ValidateRecipient(ctx context.Context, address string) (domainIsLocal, userExists, deferRejection bool, err error) {
	_, domainName, ok := strings.Cut(address, "@")
	if !ok || domainName == "" {
		return false, false, false, fmt.Errorf("invalid address %q: missing @domain", address)
	}

	if m.domainProvider == nil {
		return false, false, false, nil
	}

	d := m.domainProvider.GetDomain(domainName)
	if d == nil {
		return false, false, false, nil
	}

	domainIsLocal = true
	deferRejection = d.RecipientRejection == "data"

	userExists, err = m.authRouter.UserExists(ctx, address)
	if err != nil {
		return true, false, deferRejection, nil
	}

	return domainIsLocal, userExists, deferRejection, nil
}

// SetupAuth creates the domain provider and auth router from config.
// Returns both so the caller can pass the domain provider to New().
func SetupAuth(cfg *config.Config) (*domain.AuthRouter, domain.DomainProvider, error) {
	if cfg.DomainsPath == "" {
		return nil, nil, fmt.Errorf("domains_path is required")
	}

	agentType := cfg.Auth.AgentType
	if agentType == "" {
		agentType = "passwd"
	}

	// Domain defaults: domains without [auth] or [msgstore] sections inherit
	// these values. Matches the defaults used by credentials.Lookup.
	defaults := domain.DomainConfig{
		Auth: domain.DomainAuthConfig{
			Type:              agentType,
			CredentialBackend: cfg.Auth.CredentialBackend,
			KeyBackend:        cfg.Auth.KeyBackend,
		},
		MsgStore: domain.DomainMsgStoreConfig{
			Type:     "maildir",
			BasePath: "users",
		},
	}

	domainProvider := domain.NewFilesystemDomainProvider(cfg.DomainsPath, nil).
		WithDefaults(defaults)
	if cfg.DomainsDataPath != "" {
		domainProvider = domainProvider.WithDataPath(cfg.DomainsDataPath)
	}

	authAgent, err := auth.OpenAuthAgent(auth.AuthAgentConfig{
		Type:              agentType,
		CredentialBackend: cfg.Auth.CredentialBackend,
		KeyBackend:        cfg.Auth.KeyBackend,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open auth agent: %w", err)
	}

	return domain.NewAuthRouter(domainProvider, authAgent), domainProvider, nil
}
