// Package passwd provides a file-based authentication agent using htpasswd-like files.
package passwd

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/auth/keyseal"
)

const (
	// Key file extensions (legacy flat keyDir: {keyDir}/{user}.{key,pub})
	privateKeyExt = ".key"
	publicKeyExt  = ".pub"

	// Per-user keyring filenames in the user's own data dir
	// ({userKeyringBase}/{user}/keyring.{key,pub}). Co-located with the maildir
	// and owned by the user's uid, so the delivery process reads its own public
	// key without config-tree access.
	keyringPubFile = "keyring.pub"
	keyringKeyFile = "keyring.key"

	// Argon2id parameters for password hashing (HashPassword / verify). The
	// private-key seal KDF and blob layout live in auth/keyseal, the single
	// source of truth shared with the key-generation producer.
	saltSize      = 32
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

// userEntry represents a parsed line from the passwd file.
type userEntry struct {
	username string
	hash     string // Full hash string including algorithm prefix
	mailbox  string
	uid      uint32 // 0 = not yet assigned (pre-migration entry)
}

// Agent implements AuthenticationAgent using a passwd file and key directory.
type Agent struct {
	passwdPath string
	keyDir     string // legacy flat key dir (config tree); read-fallback only

	// userKeyringBase is the parent of per-user data dirs ({dataPath}/{domain}/users).
	// When set, per-user keyrings are read/written at {userKeyringBase}/{user}/keyring.*.
	userKeyringBase string

	mu    sync.RWMutex
	users map[string]*userEntry // Cached user entries
}

// WithUserKeyringBase sets the per-user keyring base directory (the msgstore
// user-dir parent in the writable data tree) and returns the agent for
// chaining. When set, keyrings live beside each user's maildir rather than in
// the legacy flat key directory.
func (a *Agent) WithUserKeyringBase(base string) *Agent {
	a.userKeyringBase = base
	return a
}

// NewAgent creates a new passwd-based authentication agent.
// passwdPath is the path to the passwd file.
// keyDir is the directory containing user key files.
func NewAgent(passwdPath, keyDir string) (*Agent, error) {
	a := &Agent{
		passwdPath: passwdPath,
		keyDir:     keyDir,
		users:      make(map[string]*userEntry),
	}

	if err := a.loadPasswd(); err != nil {
		return nil, err
	}

	return a, nil
}

// warnInsecurePerms logs a warning if a sensitive file is group-writable or
// world-readable. Best-effort: errors from Stat are silently ignored.
func warnInsecurePerms(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := fi.Mode().Perm()
	if perm&0o027 != 0 {
		slog.Warn("sensitive file has overly permissive permissions",
			"path", path,
			"mode", fmt.Sprintf("%04o", perm),
			"recommended", "0600 or 0640")
	}
}

// loadPasswd reads and parses the passwd file.
// A missing passwd file is treated as empty (no users), not an error.
func (a *Agent) loadPasswd() error {
	f, err := os.Open(a.passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open passwd file: %w", err)
	}
	defer func() { _ = f.Close() }()

	warnInsecurePerms(a.passwdPath)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear existing entries
	a.users = make(map[string]*userEntry)

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 2 {
			continue // Invalid line, skip
		}

		entry := &userEntry{
			username: parts[0],
			hash:     parts[1],
		}

		if len(parts) >= 3 {
			entry.mailbox = parts[2]
		} else {
			// Default mailbox is username
			entry.mailbox = parts[0]
		}

		if len(parts) >= 4 && parts[3] != "" {
			var uid uint64
			if _, err := fmt.Sscanf(parts[3], "%d", &uid); err == nil {
				entry.uid = uint32(uid)
			}
		}

		a.users[entry.username] = entry
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read passwd file: %w", err)
	}

	return nil
}

// Authenticate validates credentials and returns an AuthSession with keys.
func (a *Agent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	a.mu.RLock()
	entry, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return nil, errors.ErrUserNotFound
	}

	// Verify password against stored hash
	if !a.verifyPassword(password, entry.hash) {
		return nil, errors.ErrAuthFailed
	}

	session := &auth.AuthSession{
		User: &auth.User{
			Username: entry.username,
			Mailbox:  entry.mailbox,
		},
	}

	// Try to load and decrypt keys if they exist
	pubKey, privKey, err := a.loadKeys(username, password)
	if err == nil {
		session.PublicKey = pubKey
		session.PrivateKey = privKey
		session.EncryptionEnabled = true
	} else if err != errors.ErrKeyNotFound {
		// Key exists but couldn't be decrypted - this is an error
		return nil, err
	}
	// If ErrKeyNotFound, encryption is simply not enabled

	return session, nil
}

// Close releases any resources held by the agent.
func (a *Agent) Close() error {
	return nil
}

// UserExists checks if a user exists without authenticating.
func (a *Agent) UserExists(ctx context.Context, username string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	_, exists := a.users[username]
	return exists, nil
}

// GetPublicKey returns the public key for a user.
//
// Resolution prefers the per-user keyring ({userKeyringBase}/{user}/keyring.pub)
// and falls back to the legacy flat key dir. It is fail-closed: a key that
// EXISTS but cannot be read (e.g. EACCES) returns the underlying error, never
// ErrKeyNotFound -- so a caller (the delivery encrypt gate) does not mistake an
// inaccessible key for an absent one and silently store plaintext. The keyring
// read does not depend on the passwd file being readable by this (possibly
// privilege-dropped) process, which is what the legacy config-tree path did.
func (a *Agent) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	if a.userKeyringBase != "" {
		p := filepath.Join(a.userKeyringBase, username, keyringPubFile)
		pubKey, err := os.ReadFile(p)
		if err == nil {
			return pubKey, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read keyring public key: %w", err)
		}
		// Absent in the keyring dir -- fall through to the legacy location.
	}

	// Legacy flat key dir (config tree). Gate on user existence here, as this
	// path predates per-user keyrings.
	a.mu.RLock()
	_, exists := a.users[username]
	a.mu.RUnlock()
	if !exists {
		return nil, errors.ErrUserNotFound
	}
	if a.keyDir == "" {
		return nil, errors.ErrKeyNotFound
	}

	pubKeyPath := filepath.Join(a.keyDir, username+publicKeyExt)
	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.ErrKeyNotFound
		}
		return nil, fmt.Errorf("read public key: %w", err)
	}

	return pubKey, nil
}

// HasEncryption returns whether encryption is enabled for a user. It is
// fail-closed on an inaccessible (but present) key: that surfaces as an error
// rather than a silent false.
func (a *Agent) HasEncryption(ctx context.Context, username string) (bool, error) {
	if a.userKeyringBase != "" {
		p := filepath.Join(a.userKeyringBase, username, keyringPubFile)
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("stat keyring public key: %w", err)
		}
	}

	a.mu.RLock()
	_, exists := a.users[username]
	a.mu.RUnlock()
	if !exists || a.keyDir == "" {
		return false, nil
	}

	pubKeyPath := filepath.Join(a.keyDir, username+publicKeyExt)
	_, err := os.Stat(pubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat public key: %w", err)
	}
	return true, nil
}

// verifyPassword checks if the password matches the stored hash.
func (a *Agent) verifyPassword(password, hash string) bool {
	// Parse the hash format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	if !strings.HasPrefix(hash, "$argon2id$") {
		return false
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	// parts[0] = "" (before first $)
	// parts[1] = "argon2id"
	// parts[2] = "v=19"
	// parts[3] = "m=65536,t=3,p=4"
	// parts[4] = salt (base64)
	// parts[5] = hash (base64)

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != 19 {
		return false
	}

	var memory, time, threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Derive key from password using same parameters
	derivedKey := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), uint32(len(expectedHash)))

	// Constant-time comparison
	return subtle.ConstantTimeCompare(derivedKey, expectedHash) == 1
}

// keyFilePath resolves the path to a user key file, preferring the per-user
// keyring dir ({userKeyringBase}/{user}/{keyringFile}) and falling back to the
// legacy flat key dir ({keyDir}/{user}{legacyExt}). Fail-closed: a file present
// but unreadable at the keyring path returns an error, never ErrKeyNotFound.
// Returns ErrKeyNotFound only when the file is absent in both locations.
func (a *Agent) keyFilePath(username, keyringFile, legacyExt string) (string, error) {
	if a.userKeyringBase != "" {
		p := filepath.Join(a.userKeyringBase, username, keyringFile)
		_, err := os.Stat(p)
		if err == nil {
			return p, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat keyring %s: %w", keyringFile, err)
		}
	}
	if a.keyDir != "" {
		p := filepath.Join(a.keyDir, username+legacyExt)
		_, err := os.Stat(p)
		if err == nil {
			return p, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat key %s: %w", legacyExt, err)
		}
	}
	return "", errors.ErrKeyNotFound
}

// loadKeys loads and decrypts the user's key pair. Called at login by the
// (root) session-manager, so it can read the keyring wherever it lives.
func (a *Agent) loadKeys(username, password string) (publicKey, privateKey []byte, err error) {
	pubPath, err := a.keyFilePath(username, keyringPubFile, publicKeyExt)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	privPath, err := a.keyFilePath(username, keyringKeyFile, privateKeyExt)
	if err != nil {
		return nil, nil, err
	}
	warnInsecurePerms(privPath)
	encryptedKey, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	// Decrypt private key
	privateKey, err = decryptPrivateKey(encryptedKey, password)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// decryptPrivateKey unseals a private key using the user's password. The KDF
// and blob layout are owned by auth/keyseal, the single source of truth shared
// with the key-generation producer; Open returns the same auth/errors
// sentinels this path returned before.
func decryptPrivateKey(encryptedKey []byte, password string) ([]byte, error) {
	return keyseal.Open(encryptedKey, password)
}
