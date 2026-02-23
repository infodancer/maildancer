package maildir

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/emersion/go-maildir"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

// MaildirStore implements msgstore.MsgStore using the Maildir format.
// It uses emersion/go-maildir for low-level maildir operations.
type MaildirStore struct {
	basePath      string
	maildirSubdir string // optional subdirectory under each mailbox (e.g., "Maildir")
	pathTemplate  string // optional path template for domain-aware storage

	// deleted tracks messages marked for deletion.
	// Keys are mailbox names for INBOX, or composite keys for folders.
	deletedMu sync.Mutex
	deleted   map[string]map[string]bool // key -> uid -> deleted
}

// NewStore creates a new MaildirStore with the given base path.
// The optional maildirSubdir specifies a subdirectory under each mailbox
// (e.g., "Maildir" for paths like users/testuser/Maildir/).
// The optional pathTemplate transforms mailbox names using variables:
// {domain}, {localpart}, {email} (e.g., "{domain}/users/{localpart}").
func NewStore(basePath string, maildirSubdir string, pathTemplate string) *MaildirStore {
	return &MaildirStore{
		basePath:      basePath,
		maildirSubdir: maildirSubdir,
		pathTemplate:  pathTemplate,
		deleted:       make(map[string]map[string]bool),
	}
}

// splitEmail splits an email address into localpart and domain.
// If the email doesn't contain @, localpart is the entire input and domain is empty.
func splitEmail(email string) (localpart, domain string) {
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[:idx], email[idx+1:]
	}
	return email, ""
}

// expandMailbox applies the path template to transform a mailbox name.
// If no template is set, the mailbox is returned unchanged.
// Template variables: {domain}, {localpart}, {email}
func (s *MaildirStore) expandMailbox(mailbox string) string {
	if s.pathTemplate == "" {
		return mailbox // Backward compatible
	}
	localpart, domain := splitEmail(mailbox)
	result := s.pathTemplate
	result = strings.ReplaceAll(result, "{domain}", domain)
	result = strings.ReplaceAll(result, "{localpart}", localpart)
	result = strings.ReplaceAll(result, "{email}", mailbox)
	return result
}

// mailboxPath returns the filesystem path for a mailbox.
// Returns an error if the resulting path would escape the base directory.
func (s *MaildirStore) mailboxPath(mailbox string) (string, error) {
	// Apply path template transformation
	expandedMailbox := s.expandMailbox(mailbox)

	// Build the candidate path
	var candidate string
	if s.maildirSubdir != "" {
		candidate = filepath.Join(s.basePath, expandedMailbox, s.maildirSubdir)
	} else {
		candidate = filepath.Join(s.basePath, expandedMailbox)
	}

	// Clean both paths to normalize them
	cleanBase := filepath.Clean(s.basePath)
	cleanCandidate := filepath.Clean(candidate)

	// Verify the candidate is under the base path
	// Add separator to prevent prefix matching (e.g., /base-other matching /base)
	if !strings.HasPrefix(cleanCandidate+string(filepath.Separator), cleanBase+string(filepath.Separator)) {
		return "", errors.ErrPathTraversal
	}

	return cleanCandidate, nil
}

// ensureMaildir ensures the maildir exists, creating it if necessary.
func (s *MaildirStore) ensureMaildir(mailbox string) (maildir.Dir, error) {
	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return "", err
	}
	dir := maildir.Dir(path)

	// Check if maildir exists by checking for cur/ directory
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		// Ensure parent directories exist (needed when maildirSubdir is set)
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", err
		}
		if err := dir.Init(); err != nil {
			return "", err
		}
	}

	return dir, nil
}

// --- Common helpers ---

// listDir returns message metadata for all non-deleted messages in the given maildir path.
// deletionKey identifies which set of soft-deleted messages to filter out.
func (s *MaildirStore) listDir(path string, deletionKey string) ([]msgstore.MessageInfo, error) {
	dir := maildir.Dir(path)

	// Track which messages were in new/ (recent messages)
	recentKeys := make(map[string]bool)

	// Unseen() moves messages from new/ to cur/ and returns them
	// These messages are considered "recent"
	unseenMsgs, err := dir.Unseen()
	if err != nil {
		return nil, err
	}
	for _, msg := range unseenMsgs {
		recentKeys[msg.Key()] = true
	}

	// Now get all messages (which are all in cur/ after Unseen())
	allMsgs, err := dir.Messages()
	if err != nil {
		return nil, err
	}

	var messages []msgstore.MessageInfo
	for _, msg := range allMsgs {
		key := msg.Key()
		if s.isDeleted(deletionKey, key) {
			continue
		}

		filename := msg.Filename()
		fi, err := os.Stat(filename)
		if err != nil {
			continue // Skip on error
		}

		flags := msg.Flags()
		var flagStrings []string
		if recentKeys[key] {
			flagStrings = append(flagStrings, "\\Recent")
		}
		flagStrings = append(flagStrings, convertFlags(flags)...)

		messages = append(messages, msgstore.MessageInfo{
			UID:   key,
			Size:  fi.Size(),
			Flags: flagStrings,
		})
	}

	return messages, nil
}

// retrieveFromDir retrieves a single message from the given maildir path.
func (s *MaildirStore) retrieveFromDir(path string, uid string) (io.ReadCloser, error) {
	dir := maildir.Dir(path)
	msg, err := dir.MessageByKey(uid)
	if err != nil {
		return nil, err
	}
	return msg.Open()
}

// removeMessages permanently removes the specified messages from a maildir.
func (s *MaildirStore) removeMessages(path string, uids map[string]bool) error {
	dir := maildir.Dir(path)
	var lastErr error
	for uid := range uids {
		msg, err := dir.MessageByKey(uid)
		if err != nil {
			// Message might not exist, skip
			continue
		}
		if err := msg.Remove(); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	return lastErr
}

// convertFlags converts go-maildir flags to IMAP flag strings.
func convertFlags(flags []maildir.Flag) []string {
	var result []string
	for _, f := range flags {
		switch f {
		case maildir.FlagSeen:
			result = append(result, "\\Seen")
		case maildir.FlagReplied:
			result = append(result, "\\Answered")
		case maildir.FlagFlagged:
			result = append(result, "\\Flagged")
		case maildir.FlagDraft:
			result = append(result, "\\Draft")
		case maildir.FlagTrashed:
			result = append(result, "\\Deleted")
		}
	}
	return result
}

func (s *MaildirStore) isDeleted(key, uid string) bool {
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[key] == nil {
		return false
	}
	return s.deleted[key][uid]
}

// --- MsgStore interface ---

// Deliver implements msgstore.DeliveryAgent.
func (s *MaildirStore) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if len(envelope.Recipients) == 0 {
		return errors.ErrNoRecipients
	}

	// Read message into memory for multi-recipient delivery
	data, err := io.ReadAll(message)
	if err != nil {
		return err
	}

	var lastErr error
	delivered := 0

	for _, recipient := range envelope.Recipients {
		parsed := msgstore.ParseRecipient(recipient)

		// Load and parse the user's Sieve script (if any).
		// TODO(msgstore#14): evaluate the parsed script against this message.
		// See git.sr.ht/~emersion/go-sieve for the parser; interpreter is not yet implemented.
		if sieveCmds, err := s.loadSieveScript(parsed.Address); err != nil {
			slog.Debug("sieve script error, falling through to default delivery",
				slog.String("mailbox", parsed.Address),
				slog.String("error", err.Error()),
			)
		} else {
			_ = sieveCmds // TODO(msgstore#14): interpret
		}

		// Resolve delivery target. If the recipient has a +extension, deliver
		// to the matching Maildir++ folder — but only if it already exists.
		// The user controls which folders accept subaddressed mail: if the
		// folder does not exist, fall back to the inbox silently.
		var dir maildir.Dir
		if parsed.Extension != "" {
			if folderDir, ok := s.folderIfExists(parsed.Address, parsed.Extension); ok {
				dir = folderDir
			}
		}
		if dir == "" {
			// Deliver to inbox, creating it on first delivery.
			var err error
			dir, err = s.ensureMaildir(parsed.Address)
			if err != nil {
				lastErr = err
				continue
			}
		}

		// NewDelivery takes the directory path as a string
		delivery, err := maildir.NewDelivery(string(dir))
		if err != nil {
			lastErr = err
			continue
		}

		if _, err := io.Copy(delivery, bytes.NewReader(data)); err != nil {
			_ = delivery.Abort()
			lastErr = err
			continue
		}

		if err := delivery.Close(); err != nil {
			lastErr = err
			continue
		}

		delivered++
	}

	if delivered == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// List implements msgstore.MessageStore.
// If the maildir does not yet exist it is created automatically, so that a
// newly-provisioned user can log in before any mail has been delivered.
func (s *MaildirStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return nil, err
	}

	if _, err := s.ensureMaildir(mailbox); err != nil {
		return nil, err
	}

	return s.listDir(path, mailbox)
}

// Retrieve implements msgstore.MessageStore.
func (s *MaildirStore) Retrieve(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error) {
	if s.isDeleted(mailbox, uid) {
		return nil, errors.ErrMessageDeleted
	}

	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return nil, err
	}

	// Check if maildir exists
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrMailboxNotFound
	}

	return s.retrieveFromDir(path, uid)
}

// Delete implements msgstore.MessageStore.
func (s *MaildirStore) Delete(ctx context.Context, mailbox string, uid string) error {
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[mailbox] == nil {
		s.deleted[mailbox] = make(map[string]bool)
	}
	s.deleted[mailbox][uid] = true
	return nil
}

// Expunge implements msgstore.MessageStore.
func (s *MaildirStore) Expunge(ctx context.Context, mailbox string) error {
	s.deletedMu.Lock()
	deletedUIDs := s.deleted[mailbox]
	delete(s.deleted, mailbox)
	s.deletedMu.Unlock()

	if len(deletedUIDs) == 0 {
		return nil
	}

	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return err
	}

	// Check if maildir exists
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return errors.ErrMailboxNotFound
	}

	return s.removeMessages(path, deletedUIDs)
}

// Stat implements msgstore.MessageStore.
func (s *MaildirStore) Stat(ctx context.Context, mailbox string) (count int, totalBytes int64, err error) {
	messages, err := s.List(ctx, mailbox)
	if err != nil {
		return 0, 0, err
	}

	for _, msg := range messages {
		count++
		totalBytes += msg.Size
	}
	return count, totalBytes, nil
}

// --- FolderStore implementation ---

// folderDeletionKey returns the deletion tracking key for a folder.
// Uses a null byte separator to avoid collisions with plain mailbox keys.
func folderDeletionKey(mailbox, folder string) string {
	return mailbox + "\x00" + folder
}

// validateFolderName checks that a folder name is valid for Maildir++ storage.
// Names must be non-empty, contain only alphanumeric characters, hyphens,
// and underscores, and must not conflict with Maildir directory names.
func validateFolderName(folder string) error {
	if folder == "" {
		return errors.ErrInvalidFolderName
	}
	if len(folder) > 255 {
		return errors.ErrInvalidFolderName
	}
	if strings.HasPrefix(folder, ".") {
		return errors.ErrInvalidFolderName
	}
	// Reject reserved Maildir directory names
	switch strings.ToLower(folder) {
	case "new", "cur", "tmp":
		return errors.ErrInvalidFolderName
	}
	// Allow only alphanumeric, hyphen, underscore
	for _, r := range folder {
		if !isValidFolderChar(r) {
			return errors.ErrInvalidFolderName
		}
	}
	return nil
}

// isValidFolderChar returns true if the rune is allowed in a folder name.
func isValidFolderChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_'
}

// folderPath resolves a folder name to its Maildir++ filesystem path.
// The folder becomes a .foldername subdirectory under the mailbox path.
func (s *MaildirStore) folderPath(mailbox, folder string) (string, error) {
	if err := validateFolderName(folder); err != nil {
		return "", err
	}

	basePath, err := s.mailboxPath(mailbox)
	if err != nil {
		return "", err
	}

	// Maildir++ convention: folders are .foldername subdirectories
	candidate := filepath.Join(basePath, "."+folder)

	// Path traversal check (belt-and-suspenders with validateFolderName)
	cleanBase := filepath.Clean(basePath)
	cleanCandidate := filepath.Clean(candidate)
	if !strings.HasPrefix(cleanCandidate+string(filepath.Separator), cleanBase+string(filepath.Separator)) {
		return "", errors.ErrPathTraversal
	}

	return cleanCandidate, nil
}

// folderIfExists returns the maildir.Dir for a folder if it already exists, without
// creating it. Returns ("", false) if the folder does not exist or the name is invalid.
func (s *MaildirStore) folderIfExists(mailbox, folder string) (maildir.Dir, bool) {
	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(path, "cur")); err != nil {
		return "", false
	}
	return maildir.Dir(path), true
}

// ensureFolderMaildir ensures the folder's maildir structure exists, creating it if necessary.
// Also ensures the parent mailbox exists.
func (s *MaildirStore) ensureFolderMaildir(mailbox, folder string) (maildir.Dir, error) {
	// Ensure parent mailbox exists
	if _, err := s.ensureMaildir(mailbox); err != nil {
		return "", err
	}

	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return "", err
	}
	dir := maildir.Dir(path)

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", err
		}
		if err := dir.Init(); err != nil {
			return "", err
		}
	}

	return dir, nil
}

// CreateFolder implements msgstore.FolderStore.
func (s *MaildirStore) CreateFolder(ctx context.Context, mailbox string, folder string) error {
	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return err
	}

	// Check if folder already exists
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); err == nil {
		return errors.ErrFolderExists
	}

	// Ensure parent mailbox exists
	if _, err := s.ensureMaildir(mailbox); err != nil {
		return err
	}

	// Create the folder maildir structure
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	dir := maildir.Dir(path)
	return dir.Init()
}

// ListFolders implements msgstore.FolderStore.
func (s *MaildirStore) ListFolders(ctx context.Context, mailbox string) ([]string, error) {
	basePath, err := s.mailboxPath(mailbox)
	if err != nil {
		return nil, err
	}

	// Check if mailbox exists
	curPath := filepath.Join(basePath, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrMailboxNotFound
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}

	var folders []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, ".") {
			continue
		}
		// Verify it has valid maildir structure (contains cur/)
		folderCur := filepath.Join(basePath, name, "cur")
		if _, err := os.Stat(folderCur); os.IsNotExist(err) {
			continue
		}
		// Strip the leading dot to get the folder name
		folders = append(folders, name[1:])
	}

	return folders, nil
}

// DeleteFolder implements msgstore.FolderStore.
func (s *MaildirStore) DeleteFolder(ctx context.Context, mailbox string, folder string) error {
	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return err
	}

	// Check if folder exists
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return errors.ErrFolderNotFound
	}

	// Clear any deletion tracking for this folder
	key := folderDeletionKey(mailbox, folder)
	s.deletedMu.Lock()
	delete(s.deleted, key)
	s.deletedMu.Unlock()

	return os.RemoveAll(path)
}

// ListInFolder implements msgstore.FolderStore.
func (s *MaildirStore) ListInFolder(ctx context.Context, mailbox string, folder string) ([]msgstore.MessageInfo, error) {
	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return nil, err
	}

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrFolderNotFound
	}

	return s.listDir(path, folderDeletionKey(mailbox, folder))
}

// StatFolder implements msgstore.FolderStore.
func (s *MaildirStore) StatFolder(ctx context.Context, mailbox string, folder string) (count int, totalBytes int64, err error) {
	messages, err := s.ListInFolder(ctx, mailbox, folder)
	if err != nil {
		return 0, 0, err
	}

	for _, msg := range messages {
		count++
		totalBytes += msg.Size
	}
	return count, totalBytes, nil
}

// RetrieveFromFolder implements msgstore.FolderStore.
func (s *MaildirStore) RetrieveFromFolder(ctx context.Context, mailbox string, folder string, uid string) (io.ReadCloser, error) {
	key := folderDeletionKey(mailbox, folder)
	if s.isDeleted(key, uid) {
		return nil, errors.ErrMessageDeleted
	}

	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return nil, err
	}

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrFolderNotFound
	}

	return s.retrieveFromDir(path, uid)
}

// DeleteInFolder implements msgstore.FolderStore.
func (s *MaildirStore) DeleteInFolder(ctx context.Context, mailbox string, folder string, uid string) error {
	if err := validateFolderName(folder); err != nil {
		return err
	}

	key := folderDeletionKey(mailbox, folder)
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[key] == nil {
		s.deleted[key] = make(map[string]bool)
	}
	s.deleted[key][uid] = true
	return nil
}

// ExpungeFolder implements msgstore.FolderStore.
func (s *MaildirStore) ExpungeFolder(ctx context.Context, mailbox string, folder string) error {
	key := folderDeletionKey(mailbox, folder)

	s.deletedMu.Lock()
	deletedUIDs := s.deleted[key]
	delete(s.deleted, key)
	s.deletedMu.Unlock()

	if len(deletedUIDs) == 0 {
		return nil
	}

	path, err := s.folderPath(mailbox, folder)
	if err != nil {
		return err
	}

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return errors.ErrFolderNotFound
	}

	return s.removeMessages(path, deletedUIDs)
}

// DeliverToFolder implements msgstore.FolderStore.
func (s *MaildirStore) DeliverToFolder(ctx context.Context, mailbox string, folder string, message io.Reader) error {
	dir, err := s.ensureFolderMaildir(mailbox, folder)
	if err != nil {
		return err
	}

	delivery, err := maildir.NewDelivery(string(dir))
	if err != nil {
		return err
	}

	if _, err := io.Copy(delivery, message); err != nil {
		_ = delivery.Abort()
		return err
	}

	return delivery.Close()
}

// Compile-time interface verification.
var _ msgstore.MsgStore = (*MaildirStore)(nil)
var _ msgstore.FolderStore = (*MaildirStore)(nil)
