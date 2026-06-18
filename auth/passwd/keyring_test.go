package passwd

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// writeKeyring writes a per-user keyring public key under the user keyring base
// ({base}/{user}/keyring.pub) and returns the file path.
func writeKeyring(t *testing.T, base, user string, pub []byte) string {
	t.Helper()
	userDir := filepath.Join(base, user)
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(userDir, keyringPubFile)
	if err := os.WriteFile(p, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGetPublicKey_PrefersKeyringOverLegacy(t *testing.T) {
	const user, pass = "enctest", "correct-horse-battery-staple"
	a, _, keyDir := setupAgent(t, user, pass)
	base := t.TempDir()
	a.WithUserKeyringBase(base)

	keyringPub := []byte("KEYRING-public-key-32bytes-aaaaa")
	legacyPub := []byte("LEGACY-public-key-32bytes-bbbbbb")
	writeKeyring(t, base, user, keyringPub)
	if err := os.WriteFile(filepath.Join(keyDir, user+publicKeyExt), legacyPub, 0o640); err != nil {
		t.Fatal(err)
	}

	got, err := a.GetPublicKey(context.Background(), user)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if string(got) != string(keyringPub) {
		t.Errorf("got %q, want the keyring key %q (keyring must win over legacy)", got, keyringPub)
	}
}

func TestGetPublicKey_LegacyFallback(t *testing.T) {
	const user, pass = "enctest", "correct-horse-battery-staple"
	a, _, keyDir := setupAgent(t, user, pass)
	a.WithUserKeyringBase(t.TempDir()) // base set, but no keyring file written

	legacyPub := []byte("LEGACY-public-key-32bytes-bbbbbb")
	if err := os.WriteFile(filepath.Join(keyDir, user+publicKeyExt), legacyPub, 0o640); err != nil {
		t.Fatal(err)
	}

	got, err := a.GetPublicKey(context.Background(), user)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if string(got) != string(legacyPub) {
		t.Errorf("got %q, want legacy fallback %q", got, legacyPub)
	}
}

func TestGetPublicKey_AbsentIsNotFound(t *testing.T) {
	const user, pass = "enctest", "correct-horse-battery-staple"
	a, _, _ := setupAgent(t, user, pass)
	a.WithUserKeyringBase(t.TempDir()) // no keyring, no legacy file

	_, err := a.GetPublicKey(context.Background(), user)
	if !stderrors.Is(err, autherrors.ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound for a user with no key, got %v", err)
	}
}

// TestGetPublicKey_FailClosedOnUnreadableKeyring is the regression test for the
// fail-open bug found on the homelab: a keyring that EXISTS but is unreadable
// must NOT be reported as "no key" (which would cause the delivery gate to store
// plaintext). It must surface as an error so the caller fails closed.
func TestGetPublicKey_FailClosedOnUnreadableKeyring(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permissions; cannot simulate an unreadable key")
	}
	const user, pass = "enctest", "correct-horse-battery-staple"
	a, _, _ := setupAgent(t, user, pass)
	base := t.TempDir()
	a.WithUserKeyringBase(base)

	p := writeKeyring(t, base, user, []byte("a-real-but-unreadable-key-aaaaaa"))
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })

	_, err := a.GetPublicKey(context.Background(), user)
	if err == nil {
		t.Fatal("expected an error for an unreadable keyring, got nil (fail-open!)")
	}
	if stderrors.Is(err, autherrors.ErrKeyNotFound) || stderrors.Is(err, autherrors.ErrUserNotFound) {
		t.Errorf("unreadable key reported as absent (%v) -- must fail closed", err)
	}
}

func TestHasEncryption_Keyring(t *testing.T) {
	const user, pass = "enctest", "correct-horse-battery-staple"
	a, _, _ := setupAgent(t, user, pass)
	base := t.TempDir()
	a.WithUserKeyringBase(base)

	if has, err := a.HasEncryption(context.Background(), user); err != nil || has {
		t.Fatalf("HasEncryption before keyring: got (%v,%v), want (false,nil)", has, err)
	}
	writeKeyring(t, base, user, []byte("KEYRING-public-key-32bytes-aaaaa"))
	if has, err := a.HasEncryption(context.Background(), user); err != nil || !has {
		t.Fatalf("HasEncryption after keyring: got (%v,%v), want (true,nil)", has, err)
	}
}
