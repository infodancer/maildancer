package keys

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 32
	nonceSize     = 24
)

// GenerateKeypair generates a NaCl X25519 keypair and returns (pubKey, encryptedPrivKey, error).
// The private key is encrypted with the password using argon2id key derivation + NaCl secretbox.
// Format: salt(32B) || nonce(24B) || secretbox.Seal(privkey)
func GenerateKeypair(password string) (pubKey, encryptedPrivKey []byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate salt: %w", err)
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	var key [32]byte
	derived := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derived)

	encrypted := secretbox.Seal(nil, priv[:], &nonce, &key)

	encPriv := make([]byte, 0, saltSize+nonceSize+len(encrypted))
	encPriv = append(encPriv, salt...)
	encPriv = append(encPriv, nonce[:]...)
	encPriv = append(encPriv, encrypted...)

	return pub[:], encPriv, nil
}

// SaveKeypair writes pubKey to dir/name.pub and encryptedPrivKey to dir/name.key.
// Creates dir if needed (mode 0750). Files are mode 0640 (pub) and 0600 (key).
func SaveKeypair(dir, name string, pub, encPriv []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}

	pubPath := filepath.Join(dir, name+".pub")
	if err := os.WriteFile(pubPath, pub, 0o640); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(keyPath, encPriv, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

// LoadPublicKey reads and returns dir/name.pub content.
func LoadPublicKey(dir, name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, name+".pub"))
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return data, nil
}

// DeleteKeypair removes dir/name.pub and dir/name.key. Missing files are not errors.
func DeleteKeypair(dir, name string) error {
	for _, ext := range []string{".pub", ".key"} {
		path := filepath.Join(dir, name+ext)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return nil
}

// PublicKeyFingerprint returns the first 8 hex bytes of the public key as a fingerprint string.
// Format: "xx:xx:xx:xx:xx:xx:xx:xx"
func PublicKeyFingerprint(pub []byte) string {
	n := 8
	if len(pub) < n {
		n = len(pub)
	}
	pairs := make([]string, n)
	for i := 0; i < n; i++ {
		pairs[i] = hex.EncodeToString(pub[i : i+1])
	}
	return strings.Join(pairs, ":")
}
