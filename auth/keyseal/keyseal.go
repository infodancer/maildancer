// Package keyseal is the single seam between key producers (key generation in
// internal/admin/keys) and the key consumer (authentication in auth/passwd).
// Both go through Seal/Open here, so the at-rest representation cannot drift
// between them.
//
// As of maildancer#71, Seal/Open delegate to auth/keyring: Seal produces a
// sealed *keyring* (a one-entry, one-passphrase-slot keyring -- the degenerate
// case of the general format), and Open returns the active encryption private
// key. Open also still reads the legacy single-key blob
// (salt(32) || nonce(24) || secretbox.Seal(privKey)) so existing .key files
// keep working; they migrate to the keyring format opportunistically the next
// time they are re-sealed (e.g. on a password change or key regeneration).
//
// Scope note: at-rest encryption protects mail against disk/backup compromise.
// It does not make mail opaque to a live or compromised server -- legacy
// IMAP/POP clients require the server to be the decryption point, and SMTP
// delivery is already cleartext to the server. True opacity requires SCMP /
// sender-side encryption. See msgstore/docs/encryption.md.
package keyseal

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"

	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/auth/keyring"
	"github.com/infodancer/maildancer/internal/kdfcost"
)

// Legacy single-key seal parameters. Retained for reading pre-keyring .key
// files (and for the back-compat test that produces them). New seals use the
// keyring format, which owns its own KDF parameters in auth/keyring.
//
// The argon2id cost comes from kdfcost.Default: the legacy blob stores no
// parameters, so seal and open must agree, and they do by reading the same
// shared profile. The output and framing sizes stay const -- changing them
// would change the on-disk format.
const (
	argon2KeyLen = 32
	saltSize     = 32
	nonceSize    = 24
)

// Seal encrypts privKey under password as a new sealed keyring holding a single
// active X25519 encryption entry. The public key is derived from privKey.
func Seal(privKey []byte, password string) ([]byte, error) {
	if len(privKey) != 32 {
		return nil, autherrors.ErrInvalidKeyFormat
	}
	pub, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return keyring.Create(pub, privKey, password)
}

// Open returns the active encryption private key from a sealed blob. It accepts
// both the keyring format (current) and the legacy single-key format (so old
// .key files keep working). A keyring with no active encryption entry yields
// autherrors.ErrNoActiveKey; a malformed blob yields ErrInvalidKeyFormat; a
// wrong password or tampering yields ErrKeyDecryptFailed.
func Open(sealed []byte, password string) ([]byte, error) {
	if isKeyring(sealed) {
		kr, err := keyring.OpenWithPassword(sealed, password)
		if err != nil {
			return nil, err
		}
		e, ok := kr.ActiveEncryptionKey()
		if !ok {
			return nil, autherrors.ErrNoActiveKey
		}
		return e.PrivateKey, nil
	}
	return openLegacy(sealed, password)
}

// isKeyring reports whether the blob is the JSON keyring envelope rather than
// the legacy binary single-key layout. The legacy blob begins with 32 bytes of
// random salt, so a leading '{' reliably distinguishes the two.
func isKeyring(sealed []byte) bool {
	t := bytes.TrimLeft(sealed, " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

// sealLegacy produces the pre-keyring single-key blob. Retained so the
// back-compat read path stays exercised by tests; production seals use the
// keyring format via Seal.
func sealLegacy(privKey []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	var key [32]byte
	derived := argon2.IDKey([]byte(password), salt, kdfcost.Default.Time, kdfcost.Default.Memory, kdfcost.Default.Threads, argon2KeyLen)
	copy(key[:], derived)

	ciphertext := secretbox.Seal(nil, privKey, &nonce, &key)

	sealed := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	sealed = append(sealed, salt...)
	sealed = append(sealed, nonce[:]...)
	sealed = append(sealed, ciphertext...)
	return sealed, nil
}

// openLegacy reverses the pre-keyring single-key seal.
func openLegacy(sealed []byte, password string) ([]byte, error) {
	if len(sealed) < saltSize+nonceSize+secretbox.Overhead {
		return nil, autherrors.ErrInvalidKeyFormat
	}

	salt := sealed[:saltSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealed[saltSize:saltSize+nonceSize])
	ciphertext := sealed[saltSize+nonceSize:]

	var key [32]byte
	derived := argon2.IDKey([]byte(password), salt, kdfcost.Default.Time, kdfcost.Default.Memory, kdfcost.Default.Threads, argon2KeyLen)
	copy(key[:], derived)

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, autherrors.ErrKeyDecryptFailed
	}
	return plaintext, nil
}
