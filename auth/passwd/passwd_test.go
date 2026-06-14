package passwd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/auth/keyseal"
)

// writeKeyFiles writes a .pub file (pubKeyBytes) and a sealed .key file for
// username into keyDir, sealing plaintextPriv under password via auth/keyseal
// (the same path decryptPrivateKey unseals through).
// To exercise the decrypt-failure branch, seal under a password other than the
// user's login password -- the resulting blob will fail to decrypt.
func writeKeyFiles(t *testing.T, keyDir, username, password string, pubKeyBytes, plaintextPriv []byte) {
	t.Helper()

	// Write public key
	pubPath := filepath.Join(keyDir, username+publicKeyExt)
	if err := os.WriteFile(pubPath, pubKeyBytes, 0o640); err != nil {
		t.Fatalf("writeKeyFiles: write .pub: %v", err)
	}

	// Seal the .key under the given password via the shared keyseal path.
	// Passing a password other than the user's login password yields a blob
	// that will fail to decrypt -- exercised by the hard-fail tests.
	blob, err := keyseal.Seal(plaintextPriv, password)
	if err != nil {
		t.Fatalf("writeKeyFiles: seal: %v", err)
	}

	privPath := filepath.Join(keyDir, username+privateKeyExt)
	if err := os.WriteFile(privPath, blob, 0o640); err != nil {
		t.Fatalf("writeKeyFiles: write .key: %v", err)
	}
}

// setupAgent creates a temp passwd file, adds the given user, creates the key
// dir, and returns a ready Agent along with the dir paths.
func setupAgent(t *testing.T, username, password string) (agent *Agent, passwdPath, keyDir string) {
	t.Helper()

	dir := t.TempDir()
	passwdPath = filepath.Join(dir, "passwd")
	keyDir = filepath.Join(dir, "keys")

	if err := os.WriteFile(passwdPath, []byte(""), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := AddUser(passwdPath, username, password); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	a, err := NewAgent(passwdPath, keyDir)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	return a, passwdPath, keyDir
}

func TestAuthenticate_KeyLoading(t *testing.T) {
	const (
		username = "testuser"
		password = "correct-horse-battery-staple"
	)

	fakePub := []byte("fake-public-key-bytes")
	// Seal now derives the X25519 public key from the private scalar, so the
	// private key must be a valid 32-byte key. The public key file is read
	// back verbatim by loadKeys, so it can stay an opaque placeholder.
	fakePri := bytes.Repeat([]byte{0x42}, 32)

	t.Run("BranchA_KeysPresent_CorrectPassword", func(t *testing.T) {
		agent, _, keyDir := setupAgent(t, username, password)

		writeKeyFiles(t, keyDir, username, password, fakePub, fakePri)

		session, err := agent.Authenticate(t.Context(), username, password)
		if err != nil {
			t.Fatalf("Authenticate: unexpected error: %v", err)
		}
		defer session.Clear()

		if !session.EncryptionEnabled {
			t.Error("expected EncryptionEnabled == true when keys are present and password is correct")
		}
		if !bytes.Equal(session.PublicKey, fakePub) {
			t.Errorf("PublicKey mismatch: got %q, want %q", session.PublicKey, fakePub)
		}
		if !bytes.Equal(session.PrivateKey, fakePri) {
			t.Errorf("PrivateKey mismatch: got %q, want %q", session.PrivateKey, fakePri)
		}
	})

	t.Run("BranchB_NoKeys_EncryptionDisabled", func(t *testing.T) {
		agent, _, _ := setupAgent(t, username, password)
		// No key files written -- key dir is empty.

		session, err := agent.Authenticate(t.Context(), username, password)
		if err != nil {
			t.Fatalf("Authenticate: unexpected error: %v", err)
		}
		defer session.Clear()

		if session.EncryptionEnabled {
			t.Error("expected EncryptionEnabled == false when no key files exist")
		}
		if session.PublicKey != nil {
			t.Errorf("expected nil PublicKey, got %v", session.PublicKey)
		}
		if session.PrivateKey != nil {
			t.Errorf("expected nil PrivateKey, got %v", session.PrivateKey)
		}
	})

	t.Run("BranchC_KeysPresent_WrongPassword_AuthFails", func(t *testing.T) {
		agent, _, keyDir := setupAgent(t, username, password)

		// Seal the private key under a different password -- decryption will fail.
		writeKeyFiles(t, keyDir, username, "wrong-password-for-encryption", fakePub, fakePri)

		session, err := agent.Authenticate(t.Context(), username, password)

		// CRITICAL: a bad key must produce an error, never silently disable encryption.
		if err == nil {
			t.Fatal("SECURITY BUG: Authenticate returned nil error when private key cannot be decrypted -- encrypted account silently degraded")
		}
		if session != nil {
			t.Errorf("expected nil session on decryption failure, got %+v", session)
		}
		if err != errors.ErrKeyDecryptFailed {
			t.Errorf("expected ErrKeyDecryptFailed, got: %v", err)
		}
	})
}
