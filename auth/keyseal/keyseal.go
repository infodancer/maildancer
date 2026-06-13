// Package keyseal is the single source of truth for sealing a user's private
// key under their password. The producer (key generation in
// internal/admin/keys) and the consumer (authentication in auth/passwd) both
// go through Seal/Open here, so the argon2id KDF parameters and the on-disk
// blob layout cannot drift between them -- a drift would silently render every
// sealed key unreadable.
//
// Blob layout: salt(32) || nonce(24) || secretbox.Seal(privKey). The argon2id
// password-derived key keys an XSalsa20-Poly1305 secretbox.
//
// These parameters are the key-seal KDF, deliberately independent of the
// password-hashing parameters in auth/passwd (which are self-describing in the
// stored hash string). Keep them separate so the two costs stay independent.
package keyseal

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 32
	nonceSize     = 24
)

// Seal encrypts privKey under password. Each call uses a fresh random salt and
// nonce, so identical inputs never produce identical output. The result is
// salt(32) || nonce(24) || ciphertext.
func Seal(privKey []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	var key [32]byte
	derived := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derived)

	ciphertext := secretbox.Seal(nil, privKey, &nonce, &key)

	sealed := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	sealed = append(sealed, salt...)
	sealed = append(sealed, nonce[:]...)
	sealed = append(sealed, ciphertext...)
	return sealed, nil
}

// Open reverses Seal, deriving the key from password and the embedded salt.
// Returns autherrors.ErrInvalidKeyFormat for a blob too short to hold the
// header, and autherrors.ErrKeyDecryptFailed when authentication fails (wrong
// password or tampering).
func Open(sealed []byte, password string) ([]byte, error) {
	if len(sealed) < saltSize+nonceSize+secretbox.Overhead {
		return nil, autherrors.ErrInvalidKeyFormat
	}

	salt := sealed[:saltSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealed[saltSize:saltSize+nonceSize])
	ciphertext := sealed[saltSize+nonceSize:]

	var key [32]byte
	derived := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derived)

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, autherrors.ErrKeyDecryptFailed
	}
	return plaintext, nil
}
