package msgstore

import "context"

// AuthSession represents an authenticated user with access to keys.
// The session holds decrypted key material that should be zeroed on close.
type AuthSession struct {
	// User contains the authenticated user information.
	User *User

	// PrivateKey is the decrypted private key for this session.
	// nil if encryption is not enabled for this user.
	// This key is held in memory only during the session and should be
	// zeroed when the session ends.
	PrivateKey []byte

	// PublicKey is the user's public key for encryption.
	// nil if encryption is not enabled for this user.
	PublicKey []byte

	// EncryptionEnabled indicates whether encryption is enabled for this user.
	EncryptionEnabled bool
}

// Clear zeros out sensitive key material in the session.
// Should be called when the session ends.
func (s *AuthSession) Clear() {
	if s.PrivateKey != nil {
		for i := range s.PrivateKey {
			s.PrivateKey[i] = 0
		}
		s.PrivateKey = nil
	}
}

// AuthenticationAgent handles user authentication and key retrieval.
// Used by pop3d and imapd for authenticated sessions with key access.
// This interface replaces the simpler AuthProvider interface.
type AuthenticationAgent interface {
	// Authenticate validates credentials and returns an AuthSession with keys.
	// Returns errors.ErrAuthFailed if credentials are invalid.
	// Returns errors.ErrUserNotFound if the user does not exist.
	// The returned AuthSession contains the decrypted private key if encryption
	// is enabled for the user.
	Authenticate(ctx context.Context, username, password string) (*AuthSession, error)

	// Close releases any resources held by the agent.
	Close() error
}

// KeyProvider retrieves public keys for encryption.
// Used by smtpd to encrypt messages for recipients.
// This is a separate interface from AuthenticationAgent because smtpd
// only needs public keys, not full authentication.
type KeyProvider interface {
	// GetPublicKey returns the public key for a user.
	// Returns errors.ErrKeyNotFound if the user has no key.
	// Returns errors.ErrUserNotFound if the user does not exist.
	GetPublicKey(ctx context.Context, username string) ([]byte, error)

	// HasEncryption returns whether encryption is enabled for a user.
	// Returns false if the user does not exist or has no keys configured.
	HasEncryption(ctx context.Context, username string) (bool, error)
}
