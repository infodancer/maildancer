// Package passwd provides a file-based authentication agent using htpasswd-like files.
package passwd

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/errors"
)

const (
	// Key file extensions
	privateKeyExt = ".key"
	publicKeyExt  = ".pub"

	// Encrypted key file format: salt (32B) || nonce (24B) || ciphertext
	saltSize  = 32
	nonceSize = 24

	// Argon2id parameters for key derivation
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
}

// Agent implements AuthenticationAgent using a passwd file and key directory.
type Agent struct {
	passwdPath string
	keyDir     string

	mu    sync.RWMutex
	users map[string]*userEntry // Cached user entries
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

// loadPasswd reads and parses the passwd file.
func (a *Agent) loadPasswd() error {
	f, err := os.Open(a.passwdPath)
	if err != nil {
		return fmt.Errorf("open passwd file: %w", err)
	}
	defer func() { _ = f.Close() }()

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

		parts := strings.SplitN(line, ":", 3)
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

// GetPublicKey returns the public key for a user.
func (a *Agent) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	a.mu.RLock()
	_, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return nil, errors.ErrUserNotFound
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

// HasEncryption returns whether encryption is enabled for a user.
func (a *Agent) HasEncryption(ctx context.Context, username string) (bool, error) {
	a.mu.RLock()
	_, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return false, nil
	}

	pubKeyPath := filepath.Join(a.keyDir, username+publicKeyExt)
	_, err := os.Stat(pubKeyPath)
	return err == nil, nil
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

// loadKeys loads and decrypts the user's key pair.
func (a *Agent) loadKeys(username, password string) (publicKey, privateKey []byte, err error) {
	// Load public key
	pubKeyPath := filepath.Join(a.keyDir, username+publicKeyExt)
	publicKey, err = os.ReadFile(pubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, errors.ErrKeyNotFound
		}
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	// Load encrypted private key
	privKeyPath := filepath.Join(a.keyDir, username+privateKeyExt)
	encryptedKey, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, errors.ErrKeyNotFound
		}
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	// Decrypt private key
	privateKey, err = decryptPrivateKey(encryptedKey, password)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// decryptPrivateKey decrypts a private key using the user's password.
// File format: salt (32B) || nonce (24B) || ciphertext
func decryptPrivateKey(encryptedKey []byte, password string) ([]byte, error) {
	if len(encryptedKey) < saltSize+nonceSize+secretbox.Overhead {
		return nil, errors.ErrInvalidKeyFormat
	}

	salt := encryptedKey[:saltSize]
	var nonce [nonceSize]byte
	copy(nonce[:], encryptedKey[saltSize:saltSize+nonceSize])
	ciphertext := encryptedKey[saltSize+nonceSize:]

	// Derive key from password
	var key [32]byte
	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derivedKey)

	// Decrypt using NaCl secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, errors.ErrKeyDecryptFailed
	}

	return plaintext, nil
}
