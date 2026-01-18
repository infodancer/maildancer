package msgstore

import "context"

// AuthProvider validates user credentials.
// Used by smtpd, pop3d, and imapd for authentication.
type AuthProvider interface {
	// Authenticate validates credentials and returns user info.
	// Returns ErrAuthFailed if credentials are invalid.
	Authenticate(ctx context.Context, username, password string) (*User, error)
}

// User represents an authenticated mail user.
type User struct {
	// Username is the user's login name.
	Username string

	// Mailbox is the path or identifier for the user's mailbox.
	Mailbox string
}
