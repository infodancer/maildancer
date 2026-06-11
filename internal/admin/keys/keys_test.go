package keys_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/infodancer/maildancer/internal/admin/keys"
)

const (
	saltSize  = 32
	nonceSize = 24
	// secretbox overhead is 16 bytes (Poly1305 MAC)
	secretboxOverhead = 16
	privKeySize       = 32
)

func TestGenerateKeypair(t *testing.T) {
	pub, encPriv, err := keys.GenerateKeypair("hunter2")
	if err != nil {
		t.Fatalf("GenerateKeypair returned error: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("pubKey length = %d, want 32", len(pub))
	}
	expectedEncLen := saltSize + nonceSize + secretboxOverhead + privKeySize
	if len(encPriv) != expectedEncLen {
		t.Errorf("encPrivKey length = %d, want %d", len(encPriv), expectedEncLen)
	}
}

func TestGenerateKeypairDifferentPasswords(t *testing.T) {
	_, enc1, err := keys.GenerateKeypair("password1")
	if err != nil {
		t.Fatalf("first GenerateKeypair error: %v", err)
	}
	_, enc2, err := keys.GenerateKeypair("password2")
	if err != nil {
		t.Fatalf("second GenerateKeypair error: %v", err)
	}
	// Different passwords (and random salts/nonces) must produce different ciphertexts.
	if bytes.Equal(enc1, enc2) {
		t.Error("two GenerateKeypair calls produced identical ciphertexts")
	}
}

func TestSaveAndLoadKeypair(t *testing.T) {
	dir := t.TempDir()
	pub, encPriv, err := keys.GenerateKeypair("s3cret")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := keys.SaveKeypair(dir, "alice", pub, encPriv); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	got, err := keys.LoadPublicKey(dir, "alice")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("LoadPublicKey = %x, want %x", got, pub)
	}
}

func TestSaveKeypairCreatesDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "newdir", "subdir")

	pub, encPriv, err := keys.GenerateKeypair("pass")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := keys.SaveKeypair(dir, "bob", pub, encPriv); err != nil {
		t.Fatalf("SaveKeypair with non-existent dir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "bob.pub")); err != nil {
		t.Errorf("bob.pub not created: %v", err)
	}
}

func TestSaveKeypairFileModes(t *testing.T) {
	dir := t.TempDir()
	pub, encPriv, err := keys.GenerateKeypair("pass")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := keys.SaveKeypair(dir, "charlie", pub, encPriv); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	pubInfo, err := os.Stat(filepath.Join(dir, "charlie.pub"))
	if err != nil {
		t.Fatalf("stat .pub: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o640 {
		t.Errorf(".pub mode = %o, want 0640", pubInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "charlie.key"))
	if err != nil {
		t.Fatalf("stat .key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf(".key mode = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestDeleteKeypair(t *testing.T) {
	dir := t.TempDir()
	pub, encPriv, err := keys.GenerateKeypair("pass")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := keys.SaveKeypair(dir, "dave", pub, encPriv); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	if err := keys.DeleteKeypair(dir, "dave"); err != nil {
		t.Fatalf("DeleteKeypair: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "dave.pub")); !os.IsNotExist(err) {
		t.Error("dave.pub should be gone after DeleteKeypair")
	}
	if _, err := os.Stat(filepath.Join(dir, "dave.key")); !os.IsNotExist(err) {
		t.Error("dave.key should be gone after DeleteKeypair")
	}

	// Second delete must not return an error (missing files are OK).
	if err := keys.DeleteKeypair(dir, "dave"); err != nil {
		t.Errorf("second DeleteKeypair returned unexpected error: %v", err)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}

	fp := keys.PublicKeyFingerprint(pub)

	// Expect "xx:xx:xx:xx:xx:xx:xx:xx" -- 8 hex pairs joined by colons.
	re := regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){7}$`)
	if !re.MatchString(fp) {
		t.Errorf("fingerprint %q does not match expected format", fp)
	}

	// Verify the first byte is correct.
	want := fmt.Sprintf("%02x", pub[0])
	if fp[:2] != want {
		t.Errorf("fingerprint first byte = %q, want %q", fp[:2], want)
	}
}

func TestPublicKeyFingerprintShort(t *testing.T) {
	// A key shorter than 8 bytes should not panic; it returns what is available.
	pub := []byte{0xab, 0xcd}
	fp := keys.PublicKeyFingerprint(pub)
	if fp == "" {
		t.Error("fingerprint of short key must not be empty")
	}
	// Should be "ab:cd"
	if fp != "ab:cd" {
		t.Errorf("short fingerprint = %q, want %q", fp, "ab:cd")
	}
}
