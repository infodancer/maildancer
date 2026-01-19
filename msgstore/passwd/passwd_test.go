package passwd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/infodancer/maildancer/msgstore/errors"
)

// hashPassword creates an Argon2id hash for testing.
func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	return "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash)
}

// createTestKeyPair creates a test key pair for a user.
// Returns the public key and encrypted private key.
func createTestKeyPair(password string) (publicKey, encryptedPrivateKey []byte) {
	// Generate a fake key pair (32 bytes each for X25519)
	publicKey = make([]byte, 32)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		panic(err)
	}
	if _, err := rand.Read(privateKey); err != nil {
		panic(err)
	}

	// Encrypt private key
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	var key [32]byte
	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derivedKey)

	ciphertext := secretbox.Seal(nil, privateKey, &nonce, &key)

	encryptedPrivateKey = make([]byte, saltSize+nonceSize+len(ciphertext))
	copy(encryptedPrivateKey[:saltSize], salt)
	copy(encryptedPrivateKey[saltSize:saltSize+nonceSize], nonce[:])
	copy(encryptedPrivateKey[saltSize+nonceSize:], ciphertext)

	return publicKey, encryptedPrivateKey
}

func TestAgent_Authenticate(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "passwd-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create passwd file
	passwdFile := filepath.Join(tmpDir, "passwd")
	hash := hashPassword("secret123")
	passwdContent := "testuser:" + hash + ":/var/mail/testuser\n"
	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0600); err != nil {
		t.Fatalf("write passwd file: %v", err)
	}

	// Create key directory
	keyDir := filepath.Join(tmpDir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("create key dir: %v", err)
	}

	// Create test keys for user
	pubKey, encPrivKey := createTestKeyPair("secret123")
	if err := os.WriteFile(filepath.Join(keyDir, "testuser.pub"), pubKey, 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "testuser.key"), encPrivKey, 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	// Create agent
	agent, err := NewAgent(passwdFile, keyDir)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	ctx := context.Background()

	t.Run("valid credentials with keys", func(t *testing.T) {
		session, err := agent.Authenticate(ctx, "testuser", "secret123")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}

		if session.User.Username != "testuser" {
			t.Errorf("username = %q, want %q", session.User.Username, "testuser")
		}
		if session.User.Mailbox != "/var/mail/testuser" {
			t.Errorf("mailbox = %q, want %q", session.User.Mailbox, "/var/mail/testuser")
		}
		if !session.EncryptionEnabled {
			t.Error("encryption should be enabled")
		}
		if session.PublicKey == nil {
			t.Error("public key should not be nil")
		}
		if session.PrivateKey == nil {
			t.Error("private key should not be nil")
		}

		// Clean up sensitive data
		session.Clear()
		if session.PrivateKey != nil {
			t.Error("private key should be nil after clear")
		}
	})

	t.Run("invalid password", func(t *testing.T) {
		_, err := agent.Authenticate(ctx, "testuser", "wrongpassword")
		if err != errors.ErrAuthFailed {
			t.Errorf("err = %v, want ErrAuthFailed", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		_, err := agent.Authenticate(ctx, "unknownuser", "secret123")
		if err != errors.ErrUserNotFound {
			t.Errorf("err = %v, want ErrUserNotFound", err)
		}
	})
}

func TestAgent_Authenticate_NoKeys(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "passwd-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create passwd file
	passwdFile := filepath.Join(tmpDir, "passwd")
	hash := hashPassword("secret123")
	passwdContent := "testuser:" + hash + ":/var/mail/testuser\n"
	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0600); err != nil {
		t.Fatalf("write passwd file: %v", err)
	}

	// Create empty key directory (no keys)
	keyDir := filepath.Join(tmpDir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("create key dir: %v", err)
	}

	// Create agent
	agent, err := NewAgent(passwdFile, keyDir)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	ctx := context.Background()

	session, err := agent.Authenticate(ctx, "testuser", "secret123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if session.User.Username != "testuser" {
		t.Errorf("username = %q, want %q", session.User.Username, "testuser")
	}
	if session.EncryptionEnabled {
		t.Error("encryption should not be enabled without keys")
	}
	if session.PublicKey != nil {
		t.Error("public key should be nil without keys")
	}
	if session.PrivateKey != nil {
		t.Error("private key should be nil without keys")
	}
}

func TestAgent_GetPublicKey(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "passwd-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create passwd file
	passwdFile := filepath.Join(tmpDir, "passwd")
	hash := hashPassword("secret123")
	passwdContent := "testuser:" + hash + ":/var/mail/testuser\n"
	passwdContent += "nokeysuser:" + hash + ":/var/mail/nokeysuser\n"
	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0600); err != nil {
		t.Fatalf("write passwd file: %v", err)
	}

	// Create key directory
	keyDir := filepath.Join(tmpDir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("create key dir: %v", err)
	}

	// Create test keys for testuser only
	pubKey, _ := createTestKeyPair("secret123")
	if err := os.WriteFile(filepath.Join(keyDir, "testuser.pub"), pubKey, 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	// Create agent
	agent, err := NewAgent(passwdFile, keyDir)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	ctx := context.Background()

	t.Run("user with key", func(t *testing.T) {
		key, err := agent.GetPublicKey(ctx, "testuser")
		if err != nil {
			t.Fatalf("get public key: %v", err)
		}
		if len(key) != 32 {
			t.Errorf("key length = %d, want 32", len(key))
		}
	})

	t.Run("user without key", func(t *testing.T) {
		_, err := agent.GetPublicKey(ctx, "nokeysuser")
		if err != errors.ErrKeyNotFound {
			t.Errorf("err = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		_, err := agent.GetPublicKey(ctx, "unknownuser")
		if err != errors.ErrUserNotFound {
			t.Errorf("err = %v, want ErrUserNotFound", err)
		}
	})
}

func TestAgent_HasEncryption(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "passwd-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create passwd file
	passwdFile := filepath.Join(tmpDir, "passwd")
	hash := hashPassword("secret123")
	passwdContent := "testuser:" + hash + ":/var/mail/testuser\n"
	passwdContent += "nokeysuser:" + hash + ":/var/mail/nokeysuser\n"
	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0600); err != nil {
		t.Fatalf("write passwd file: %v", err)
	}

	// Create key directory
	keyDir := filepath.Join(tmpDir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("create key dir: %v", err)
	}

	// Create test keys for testuser only
	pubKey, _ := createTestKeyPair("secret123")
	if err := os.WriteFile(filepath.Join(keyDir, "testuser.pub"), pubKey, 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	// Create agent
	agent, err := NewAgent(passwdFile, keyDir)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	ctx := context.Background()

	t.Run("user with key", func(t *testing.T) {
		has, err := agent.HasEncryption(ctx, "testuser")
		if err != nil {
			t.Fatalf("has encryption: %v", err)
		}
		if !has {
			t.Error("should have encryption")
		}
	})

	t.Run("user without key", func(t *testing.T) {
		has, err := agent.HasEncryption(ctx, "nokeysuser")
		if err != nil {
			t.Fatalf("has encryption: %v", err)
		}
		if has {
			t.Error("should not have encryption")
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		has, err := agent.HasEncryption(ctx, "unknownuser")
		if err != nil {
			t.Fatalf("has encryption: %v", err)
		}
		if has {
			t.Error("unknown user should not have encryption")
		}
	})
}

func TestDecryptPrivateKey_InvalidFormat(t *testing.T) {
	// Too short
	_, err := decryptPrivateKey([]byte("short"), "password")
	if err != errors.ErrInvalidKeyFormat {
		t.Errorf("err = %v, want ErrInvalidKeyFormat", err)
	}
}

func TestDecryptPrivateKey_WrongPassword(t *testing.T) {
	_, encPrivKey := createTestKeyPair("correctpassword")

	_, err := decryptPrivateKey(encPrivKey, "wrongpassword")
	if err != errors.ErrKeyDecryptFailed {
		t.Errorf("err = %v, want ErrKeyDecryptFailed", err)
	}
}
