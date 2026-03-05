package msgstore

import (
	"context"
	"io"
	"time"
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

	// InternalDate is the date the message was received by the server.
	// Used by IMAP FETCH INTERNALDATE and date-based SEARCH criteria.
	InternalDate time.Time
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

	// RenameFolder renames a folder within a mailbox.
	// Returns ErrFolderNotFound if oldName does not exist.
	// Returns ErrFolderExists if newName already exists.
	// INBOX cannot be renamed.
	RenameFolder(ctx context.Context, mailbox string, oldName string, newName string) error

	// AppendToFolder stores a message in a folder with explicit flags and internal date.
	// Used by the IMAP APPEND command. Returns the UID assigned to the new message.
	// Distinct from DeliverToFolder which is for smtpd routing (no flags/date control).
	// folder may be "INBOX" to append to the inbox.
	AppendToFolder(ctx context.Context, mailbox string, folder string, r io.Reader, flags []string, date time.Time) (uid string, err error)

	// SetFlagsInFolder replaces the complete flag set on a message.
	// flags uses IMAP flag strings (e.g. "\\Seen", "\\Deleted", "\\Answered").
	// folder may be "INBOX" to operate on inbox messages.
	SetFlagsInFolder(ctx context.Context, mailbox string, folder string, uid string, flags []string) error

	// CopyMessage copies a message to another folder within the same mailbox.
	// Returns the UID assigned to the copy in destFolder.
	// srcFolder may be "INBOX"; destFolder may be "INBOX".
	CopyMessage(ctx context.Context, mailbox string, srcFolder string, uid string, destFolder string) (newUID string, err error)

	// UIDValidity returns the UIDValidity value for a folder.
	// The value must remain constant for a given folder as long as UIDs have
	// not been reassigned. folder may be "INBOX".
	UIDValidity(ctx context.Context, mailbox string, folder string) (uint32, error)
}

// FolderSpec defines a default folder with an optional IMAP SPECIAL-USE attribute (RFC 6154).
type FolderSpec struct {
	// Name is the folder name (e.g., "Junk", "Sent").
	Name string

	// SpecialUse is the IMAP SPECIAL-USE attribute (e.g., "\\Junk").
	// Empty if the folder has no RFC 6154 attribute.
	SpecialUse string
}

// DefaultFolders lists the folders that should be created for every new mailbox.
// Folders with SpecialUse attributes are discoverable by IMAP clients via LIST.
var DefaultFolders = []FolderSpec{
	{Name: "Junk", SpecialUse: "\\Junk"},
	{Name: "Trash", SpecialUse: "\\Trash"},
	{Name: "Sent", SpecialUse: "\\Sent"},
	{Name: "Drafts", SpecialUse: "\\Drafts"},
	{Name: "List", SpecialUse: ""},
	{Name: "Bulk", SpecialUse: ""},
}

// FolderAliases maps well-known synonyms to canonical folder names.
// Used by IMAP backends to normalize client-hardcoded folder names
// (e.g., "Spam" → "Junk") so only one physical folder exists.
var FolderAliases = map[string]string{
	"Spam": "Junk",
}

// ResolveFolder returns the canonical folder name for a given name.
// If the name is a known alias, the canonical name is returned.
// Otherwise the original name is returned unchanged.
func ResolveFolder(name string) string {
	if canonical, ok := FolderAliases[name]; ok {
		return canonical
	}
	return name
}

// SpecialUseFor returns the IMAP SPECIAL-USE attribute for the given folder name.
// Returns an empty string if the folder has no SPECIAL-USE attribute.
func SpecialUseFor(folderName string) string {
	for _, f := range DefaultFolders {
		if f.Name == folderName {
			return f.SpecialUse
		}
	}
	return ""
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
