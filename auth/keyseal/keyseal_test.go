package keyseal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

func TestSealOpen_RoundTrip(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}

	sealed, err := Seal(priv, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Layout: salt(32) || nonce(24) || ciphertext(priv+16). For a 32-byte
	// private key the sealed blob is exactly 32+24+32+16 = 104 bytes.
	if len(sealed) != saltSize+nonceSize+32+16 {
		t.Errorf("sealed length = %d, want 104", len(sealed))
	}

	out, err := Open(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(out, priv) {
		t.Error("round-tripped private key does not match original")
	}
}

func TestSeal_DistinctSaltPerCall(t *testing.T) {
	priv := bytes.Repeat([]byte{0x42}, 32)
	a, err := Seal(priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Random salt + nonce per call: identical inputs must not produce
	// identical blobs (no deterministic seal, no nonce reuse).
	if bytes.Equal(a, b) {
		t.Error("two seals of the same key+password produced identical bytes")
	}
}

func TestOpen_WrongPassword(t *testing.T) {
	priv := bytes.Repeat([]byte{0x01}, 32)
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
