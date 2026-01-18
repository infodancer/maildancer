package msgstore

import (
	"context"
	"io"
)

// MessageStore provides read access to stored messages.
// Used by pop3d and imapd for message retrieval.
type MessageStore interface {
	// List returns message metadata for a mailbox.
	List(ctx context.Context, mailbox string) ([]MessageInfo, error)

	// Retrieve returns the full message content.
	// The caller is responsible for closing the returned ReadCloser.
	Retrieve(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error)

	// Delete marks a message for deletion.
	// The message is not permanently removed until Expunge is called.
	Delete(ctx context.Context, mailbox string, uid string) error

	// Expunge permanently removes all messages marked for deletion.
	Expunge(ctx context.Context, mailbox string) error

	// Stat returns mailbox statistics.
	// count is the number of messages, totalBytes is the sum of all message sizes.
	Stat(ctx context.Context, mailbox string) (count int, totalBytes int64, err error)
}

// MessageInfo contains metadata about a stored message.
type MessageInfo struct {
	// UID is the unique identifier for the message within the mailbox.
	UID string

	// Size is the message size in bytes.
	Size int64

	// Flags contains message flags (e.g., "\Seen", "\Deleted", "\Answered").
	Flags []string
}

// DecryptingStore wraps MessageStore to provide transparent decryption.
// Used by pop3d to decrypt messages during an authenticated session.
// The session key must be set after successful authentication.
type DecryptingStore interface {
	MessageStore

	// SetSessionKey provides the user's decrypted private key for this session.
	// Called after successful authentication to enable message decryption.
	// The key is held in memory only for the duration of the session.
	SetSessionKey(key []byte)

	// ClearSessionKey removes the session key from memory.
	// Called when the session ends to ensure key material is not retained.
	ClearSessionKey()
}
