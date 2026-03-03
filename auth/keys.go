package auth

import "errors"

// DeriveKeyPair derives an X25519 key pair from a user's password and username.
// The salt parameter provides domain separation and should be stored per-user.
//
// Currently a stub — returns an error until a KDF (Argon2id or HKDF) is chosen
// and implemented. The interface is stable; callers should treat the output as
// opaque 32-byte keys compatible with NaCl box (golang.org/x/crypto/nacl/box).
//
// Future: this function will also support unlocking a per-user keyring protected
// by the password, rather than deriving keys directly from the password.
func DeriveKeyPair(password, username string, salt []byte) (pub, priv []byte, err error) {
	return nil, nil, errors.New("DeriveKeyPair: not yet implemented")
}
