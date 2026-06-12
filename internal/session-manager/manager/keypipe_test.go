package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func TestKeyPipe_EnvelopeRoundTrip(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}

	r, err := keyPipe(priv)
	if err != nil {
		t.Fatalf("keyPipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Decode exactly the way cmd/mail-session does: JSON envelope with a
	// version and a base64 []byte key.
	var env struct {
		Version int    `json:"version"`
		Key     []byte `json:"key"`
	}
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Version != 1 {
		t.Errorf("version: want 1, got %d", env.Version)
	}
	if !bytes.Equal(env.Key, priv) {
		t.Error("key does not round-trip through the pipe")
	}
}

// provisionUserKeys writes alice's .pub and password-encrypted .key files in
// the same format the passwd agent reads (salt || nonce || secretbox under
// an Argon2id password-derived key). Returns the plaintext private key.
func provisionUserKeys(t *testing.T, keyDir, password string) []byte {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32))

	encKey := append(append(append([]byte{}, salt...), nonce[:]...),
		secretbox.Seal(nil, priv[:], &nonce, &key)...)

	if err := os.WriteFile(filepath.Join(keyDir, "alice.pub"), pub[:], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "alice.key"), encKey, 0600); err != nil {
		t.Fatal(err)
	}
	return priv[:]
}

// TestLogin_PrivateKeyReachesSpawn drives the real auth path (AuthRouter over
// a filesystem domain fixture) and asserts the decrypted private key from the
// auth session is handed to the spawn hook.
func TestLogin_PrivateKeyReachesSpawn(t *testing.T) {
	base := t.TempDir()
	domainDir := filepath.Join(base, "example.com")
	keyDir := filepath.Join(domainDir, "keys")
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.HashPassword("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"),
		[]byte("alice:"+hash+":alice\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	wantKey := provisionUserKeys(t, keyDir, "testpass")

	provider := domain.NewFilesystemDomainProvider(base, nil)
	t.Cleanup(func() { _ = provider.Close() })

	m := &Manager{
		cfg:        &config.Config{},
		authRouter: domain.NewAuthRouter(provider, nil),
		metrics:    &metrics.NoopCollector{},
		byToken:    make(map[string]*sessionEntry),
		byUser:     make(map[string]*sessionEntry),
	}

	var gotKey []byte
	m.spawnFn = func(username, mailbox string, privKey []byte) (*sessionEntry, error) {
		// Copy: Login zeroes the buffer after spawning.
		gotKey = append([]byte(nil), privKey...)
		return &sessionEntry{
			username:  username,
			mailbox:   mailbox,
			mailboxCl: &mockMailboxClient{},
			folderCl:  &mockFolderClient{},
			watchCl:   &mockWatchClient{},
			refCount:  1,
		}, nil
	}

	if _, err := m.Login(context.Background(), "alice@example.com", "testpass"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !bytes.Equal(gotKey, wantKey) {
		t.Errorf("spawn did not receive the decrypted private key (got %d bytes)", len(gotKey))
	}
}

// TestLogin_NoKeysSpawnsWithoutKey: a user without provisioned keys logs in
// fine and the spawn hook receives no key material.
func TestLogin_NoKeysSpawnsWithoutKey(t *testing.T) {
	base := t.TempDir()
	domainDir := filepath.Join(base, "example.com")
	if err := os.MkdirAll(filepath.Join(domainDir, "keys"), 0755); err != nil {
		t.Fatal(err)
	}
	hash, err := passwd.HashPassword("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"),
		[]byte("alice:"+hash+":alice\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	provider := domain.NewFilesystemDomainProvider(base, nil)
	t.Cleanup(func() { _ = provider.Close() })

	m := &Manager{
		cfg:        &config.Config{},
		authRouter: domain.NewAuthRouter(provider, nil),
		metrics:    &metrics.NoopCollector{},
		byToken:    make(map[string]*sessionEntry),
		byUser:     make(map[string]*sessionEntry),
	}

	var gotKey []byte
	m.spawnFn = func(username, mailbox string, privKey []byte) (*sessionEntry, error) {
		gotKey = append([]byte(nil), privKey...)
		return &sessionEntry{
			username:  username,
			mailbox:   mailbox,
			mailboxCl: &mockMailboxClient{},
			folderCl:  &mockFolderClient{},
			watchCl:   &mockWatchClient{},
			refCount:  1,
		}, nil
	}

	if _, err := m.Login(context.Background(), "alice@example.com", "testpass"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(gotKey) != 0 {
		t.Errorf("want no key for keyless user, got %d bytes", len(gotKey))
	}
}
