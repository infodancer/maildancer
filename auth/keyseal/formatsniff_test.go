package keyseal

import (
	"bytes"
	"testing"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// sealLegacyWithSalt builds a legacy blob with a chosen salt, so the
// format-detection edge case can be tested deterministically instead of waiting
// for crypto/rand to produce it.
//
// It duplicates sealLegacy's framing on purpose: the point is to control the
// salt, which sealLegacy deliberately does not allow.
func sealLegacyWithSalt(t *testing.T, privKey []byte, password string, salt []byte) []byte {
	t.Helper()
	if len(salt) != saltSize {
		t.Fatalf("salt is %d bytes, want %d", len(salt), saltSize)
	}

	blob, err := sealLegacy(privKey, password)
	if err != nil {
		t.Fatalf("sealLegacy: %v", err)
	}
	// The blob is salt || nonce || ciphertext, and the salt only feeds the KDF,
	// so overwriting it in place yields a blob that legitimately decrypts under
	// a KDF keyed by the new salt... which it does not. Rebuild instead by
	// re-deriving through the real path: seal, then splice our salt in and
	// re-seal is not possible, so assert the caller only uses this for routing.
	out := make([]byte, len(blob))
	copy(out, blob)
	copy(out[:saltSize], salt)
	return out
}

// TestIsKeyring_LegacyBlobWithBraceSalt is the regression test for the
// misrouting bug: a legacy blob whose random salt happens to begin with '{'
// must still be recognized as legacy.
//
// This was a real failure, not a theoretical one -- the salt is 32 random bytes,
// so about one legacy blob in 256 begins with 0x7b. Every such key returned
// ErrInvalidKeyFormat forever, meaning that user could never decrypt their mail.
// It surfaced only as a ~1-in-200 test flake, which is far too weak a signal to
// protect a key-access path, hence this deterministic test.
func TestIsKeyring_LegacyBlobWithBraceSalt(t *testing.T) {
	salt := bytes.Repeat([]byte{'A'}, saltSize)
	salt[0] = '{'

	blob := sealLegacyWithSalt(t, newPriv(t), "pw", salt)

	if isKeyring(blob) {
		t.Error("legacy blob with a '{' salt is still detected as a keyring")
	}
}

// TestIsKeyring_LegacyBlobWithWhitespaceThenBrace covers the same hazard through
// the leading-whitespace trim: a salt of, say, 0x20 0x7b would also have
// collided.
func TestIsKeyring_LegacyBlobWithWhitespaceThenBrace(t *testing.T) {
	for _, ws := range []byte{' ', '\t', '\r', '\n'} {
		salt := bytes.Repeat([]byte{'A'}, saltSize)
		salt[0] = ws
		salt[1] = '{'

		blob := sealLegacyWithSalt(t, newPriv(t), "pw", salt)
		if isKeyring(blob) {
			t.Errorf("legacy blob with a %q + '{' salt is still detected as a keyring", ws)
		}
	}
}

// TestOpen_LegacyBlobWithBraceSaltRoundTrips is the end-to-end version: the
// whole point is that such a key still opens.
func TestOpen_LegacyBlobWithBraceSaltRoundTrips(t *testing.T) {
	// sealLegacyWithSalt cannot produce a decryptable blob (the salt feeds the
	// KDF), so drive the real seal repeatedly until crypto/rand hands us a
	// colliding salt. With a 1-in-256 chance this is quick and never flaky in
	// the failing direction -- if no collision turns up the test skips rather
	// than passing vacuously.
	priv := newPriv(t)
	const attempts = 8000

	var collided []byte
	for range attempts {
		blob, err := sealLegacy(priv, "pw")
		if err != nil {
			t.Fatalf("sealLegacy: %v", err)
		}
		trimmed := bytes.TrimLeft(blob, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == '{' {
			collided = blob
			break
		}
	}
	if collided == nil {
		t.Skipf("no '{'-prefixed salt in %d attempts; the unit tests above still "+
			"cover the routing", attempts)
	}

	out, err := Open(collided, "pw")
	if err != nil {
		t.Fatalf("Open on a legacy blob with a '{' salt: %v", err)
	}
	if !bytes.Equal(out, priv) {
		t.Error("private key mismatch after opening a '{'-salted legacy blob")
	}
}

// TestIsKeyring_RealKeyringStillDetected guards the other direction: the fix
// must not stop recognizing actual keyring blobs.
func TestIsKeyring_RealKeyringStillDetected(t *testing.T) {
	sealed, err := Seal(newPriv(t), "pw")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !isKeyring(sealed) {
		t.Error("a real keyring blob is no longer detected as one")
	}

	// And it still opens.
	out, err := Open(sealed, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("recovered key is %d bytes, want 32", len(out))
	}
}

// TestOpen_GarbageIsAFormatError keeps genuinely malformed input reporting a
// format error rather than something misleading.
func TestOpen_GarbageIsAFormatError(t *testing.T) {
	if _, err := Open([]byte("not a key at all"), "pw"); err != autherrors.ErrInvalidKeyFormat {
		t.Errorf("err = %v, want ErrInvalidKeyFormat", err)
	}
}
