package msgstore

// User represents an authenticated mail user.
type User struct {
	// Username is the user's login name.
	Username string

	// Mailbox is the path or identifier for the user's mailbox.
	Mailbox string
}
