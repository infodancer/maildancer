package auth

// User represents an authenticated mail user.
type User struct {
	// Username is the user's login name.
	Username string

	// Mailbox is the path or identifier for the user's mailbox.
	Mailbox string
}

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
