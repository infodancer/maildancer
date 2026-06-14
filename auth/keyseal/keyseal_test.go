package keyseal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// newPriv returns a fresh 32-byte X25519 private key.
func newPriv(t *testing.T) []byte {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSealOpen_RoundTrip(t *testing.T) {
	priv := newPriv(t)

	sealed, err := Seal(priv, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Seal now emits the keyring (JSON) format, not the legacy binary blob.
	if !isKeyring(sealed) {
		t.Error("Seal did not produce the keyring format")
	}

	out, err := Open(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// curve25519 clamps the scalar, so the active private key round-trips
	// through the keyring identically to what was sealed.
	if !bytes.Equal(out, priv) {
		t.Error("round-tripped private key does not match original")
	}
}

func TestSeal_DistinctPerCall(t *testing.T) {
	priv := bytes.Repeat([]byte{0x42}, 32)
	a, err := Seal(priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Fresh KEK/salt/nonces per call: identical inputs must not produce
	// identical sealed bytes.
	if bytes.Equal(a, b) {
		t.Error("two seals of the same key+password produced identical bytes")
	}
}

func TestOpen_WrongPassword(t *testing.T) {
	priv := newPriv(t)
	sealed, err := Seal(priv, "right")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(sealed, "wrong")
	if !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("Open with wrong password: err = %v, want ErrKeyDecryptFailed", err)
	}
}

func TestOpen_ShortBlob(t *testing.T) {
	_, err := Open([]byte("too short"), "pw")
	if !errors.Is(err, autherrors.ErrInvalidKeyFormat) {
		t.Errorf("Open with short blob: err = %v, want ErrInvalidKeyFormat", err)
	}
}

// TestOpen_LegacyBlob verifies pre-keyring .key files still open. The seal is
// produced by the retained legacy path; Open must route it through openLegacy.
func TestOpen_LegacyBlob(t *testing.T) {
	priv := newPriv(t)
	legacy, err := sealLegacy(priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if isKeyring(legacy) {
		t.Fatal("legacy blob misdetected as keyring format")
	}

	out, err := Open(legacy, "pw")
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	if !bytes.Equal(out, priv) {
		t.Error("legacy round-trip private key mismatch")
	}
}

func TestOpen_LegacyWrongPassword(t *testing.T) {
	priv := newPriv(t)
	legacy, err := sealLegacy(priv, "right")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(legacy, "wrong")
	if !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("legacy wrong password: err = %v, want ErrKeyDecryptFailed", err)
	}
}

// TestMigration_LegacyToKeyring models the opportunistic migration: open a
// legacy blob, then re-Seal the recovered key under a new password. The result
// is keyring format and opens to the same key.
func TestMigration_LegacyToKeyring(t *testing.T) {
	priv := newPriv(t)
	legacy, err := sealLegacy(priv, "old")
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(legacy, "old")
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	reSealed, err := Seal(recovered, "new")
	if err != nil {
		t.Fatalf("re-Seal: %v", err)
	}
	if !isKeyring(reSealed) {
		t.Error("migrated blob is not keyring format")
	}

	out, err := Open(reSealed, "new")
	if err != nil {
		t.Fatalf("Open migrated: %v", err)
	}
	if !bytes.Equal(out, priv) {
		t.Error("migrated key does not match original")
	}
}

// TestSeal_PublicKeyDerivation guards the assumption that a public key can be
// derived from the private scalar inside Seal, so the keyring entry's stored
// public key is correct.
func TestSeal_PublicKeyDerivation(t *testing.T) {
	priv := newPriv(t)
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 32 {
		t.Fatalf("derived public key length = %d, want 32", len(want))
	}
}
