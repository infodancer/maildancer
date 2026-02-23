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

// FolderStore provides folder hierarchy operations within a user's mailbox.
// Implementations use Maildir++ conventions (.foldername subdirectories).
// Consumers that need folder support should type-assert to FolderStore.
type FolderStore interface {
	// CreateFolder creates a new folder within a mailbox.
	// Returns ErrFolderExists if the folder already exists.
	CreateFolder(ctx context.Context, mailbox string, folder string) error

	// ListFolders returns the names of all folders within a mailbox.
	// INBOX is implicit and not included in the returned list.
	ListFolders(ctx context.Context, mailbox string) ([]string, error)

	// DeleteFolder removes a folder and all messages within it.
	// Returns ErrFolderNotFound if the folder does not exist.
	DeleteFolder(ctx context.Context, mailbox string, folder string) error

	// ListInFolder returns message metadata for all messages in a folder.
	ListInFolder(ctx context.Context, mailbox string, folder string) ([]MessageInfo, error)

	// StatFolder returns message count and total size for a folder.
	StatFolder(ctx context.Context, mailbox string, folder string) (count int, totalBytes int64, err error)

	// RetrieveFromFolder returns the full message content from a folder.
	// The caller is responsible for closing the returned ReadCloser.
	RetrieveFromFolder(ctx context.Context, mailbox string, folder string, uid string) (io.ReadCloser, error)

	// DeleteInFolder marks a message in a folder for deletion.
	// The message is not permanently removed until ExpungeFolder is called.
	DeleteInFolder(ctx context.Context, mailbox string, folder string, uid string) error

	// ExpungeFolder permanently removes all messages marked for deletion in a folder.
	ExpungeFolder(ctx context.Context, mailbox string, folder string) error

	// DeliverToFolder delivers a message directly to a specific folder.
	// Used by routing rules (SIEVE, user config) after deciding the target folder.
	DeliverToFolder(ctx context.Context, mailbox string, folder string, message io.Reader) error
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
