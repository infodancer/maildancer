package auth

import "context"

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

	// UserExists checks if a user exists without authenticating.
	// Returns true if the user exists, false otherwise.
	// Returns an error only for backend failures, not for missing users.
	UserExists(ctx context.Context, username string) (bool, error)

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
