package maildir

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
// Returns an error if the resulting path would escape the base directory,
// or if the mailbox is not a fully-qualified address (localpart@domain).
func (s *MaildirStore) mailboxPath(mailbox string) (string, error) {
	// Enforce the address contract: all mailbox identifiers must be fully-qualified.
	if !strings.Contains(mailbox, "@") {
		return "", errors.ErrInvalidAddress
	}

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
			UID:          key,
			Size:         fi.Size(),
			Flags:        flagStrings,
			InternalDate: fi.ModTime(),
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
	if !strings.Contains(mailbox, "@") {
		return errors.ErrInvalidAddress
	}

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

// folderOrInboxPath returns the filesystem path for a folder or INBOX.
// When folder is "INBOX" (case-insensitive), returns the mailbox root path.
func (s *MaildirStore) folderOrInboxPath(mailbox, folder string) (string, error) {
	if strings.EqualFold(folder, "INBOX") {
		return s.mailboxPath(mailbox)
	}
	return s.folderPath(mailbox, folder)
}

// convertFlagsFromIMAP converts IMAP flag strings to go-maildir flags.
// Unknown flag strings are silently ignored.
func convertFlagsFromIMAP(flags []string) []maildir.Flag {
	var result []maildir.Flag
	for _, f := range flags {
		switch f {
		case "\\Seen":
			result = append(result, maildir.FlagSeen)
		case "\\Answered":
			result = append(result, maildir.FlagReplied)
		case "\\Flagged":
			result = append(result, maildir.FlagFlagged)
		case "\\Draft":
			result = append(result, maildir.FlagDraft)
		case "\\Deleted":
			result = append(result, maildir.FlagTrashed)
		}
	}
	return result
}

// RenameFolder implements msgstore.FolderStore.
func (s *MaildirStore) RenameFolder(ctx context.Context, mailbox string, oldName string, newName string) error {
	oldPath, err := s.folderPath(mailbox, oldName)
	if err != nil {
		return err
	}
	newPath, err := s.folderPath(mailbox, newName)
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(oldPath, "cur")); os.IsNotExist(err) {
		return errors.ErrFolderNotFound
	}
	if _, err := os.Stat(filepath.Join(newPath, "cur")); err == nil {
		return errors.ErrFolderExists
	}

	// Clear deletion tracking for the old name.
	key := folderDeletionKey(mailbox, oldName)
	s.deletedMu.Lock()
	delete(s.deleted, key)
	s.deletedMu.Unlock()

	return os.Rename(oldPath, newPath)
}

// infoFromFlags formats the maildir info field from a list of flags.
// Result is "2,FLAGCHARS" where FLAGCHARS are sorted per maildir spec.
func infoFromFlags(flags []maildir.Flag) string {
	chars := make([]byte, 0, len(flags))
	for _, f := range flags {
		chars = append(chars, byte(f))
	}
	sort.Slice(chars, func(i, j int) bool { return chars[i] < chars[j] })
	return "2," + string(chars)
}

// moveNewToCurWithFlags moves a message from new/ to cur/ with the given flags.
// Used to make an appended or flag-modified message visible in cur/ immediately.
func moveNewToCurWithFlags(dirPath string, key string, flags []maildir.Flag) error {
	srcPath := filepath.Join(dirPath, "new", key)
	// ':' is the maildir info separator on POSIX systems (see maildir spec).
	dstBasename := key + ":" + infoFromFlags(flags)
	dstPath := filepath.Join(dirPath, "cur", dstBasename)
	return os.Rename(srcPath, dstPath)
}

// AppendToFolder implements msgstore.FolderStore.
func (s *MaildirStore) AppendToFolder(ctx context.Context, mailbox string, folder string, r io.Reader, flags []string, date time.Time) (string, error) {
	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return "", err
	}

	dir := maildir.Dir(path)
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}
	if err := dir.Init(); err != nil && !os.IsExist(err) {
		return "", err
	}

	// Snapshot new/ before delivery to identify the resulting key.
	newDir := filepath.Join(path, "new")
	beforeKeys, err := maildirNewKeys(newDir)
	if err != nil {
		return "", err
	}

	delivery, err := maildir.NewDelivery(path)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(delivery, r); err != nil {
		_ = delivery.Abort()
		return "", err
	}
	if err := delivery.Close(); err != nil {
		return "", err
	}

	// Find the newly added key in new/.
	key, err := maildirNewKey(newDir, beforeKeys)
	if err != nil {
		return "", err
	}

	// Move from new/ to cur/ with the requested flags. IMAP APPEND messages
	// are explicitly placed by the client and must be immediately accessible.
	if err := moveNewToCurWithFlags(path, key, convertFlagsFromIMAP(flags)); err != nil {
		return "", err
	}

	return key, nil
}

// maildirNewKeys returns the set of filenames currently in the new/ directory.
func maildirNewKeys(newDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(newDir)
	if os.IsNotExist(err) {
		return make(map[string]bool), nil
	}
	if err != nil {
		return nil, err
	}
	keys := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			keys[e.Name()] = true
		}
	}
	return keys, nil
}

// maildirNewKey finds the single new entry in new/ not present in beforeKeys.
func maildirNewKey(newDir string, beforeKeys map[string]bool) (string, error) {
	entries, err := os.ReadDir(newDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && !beforeKeys[e.Name()] {
			return e.Name(), nil
		}
	}
	return "", errors.ErrMessageNotFound
}

// SetFlagsInFolder implements msgstore.FolderStore.
func (s *MaildirStore) SetFlagsInFolder(ctx context.Context, mailbox string, folder string, uid string, flags []string) error {
	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return err
	}
	mdFlags := convertFlagsFromIMAP(flags)
	dir := maildir.Dir(path)

	// Try cur/ first (most messages live here).
	msg, err := dir.MessageByKey(uid)
	if err == nil {
		return msg.SetFlags(mdFlags)
	}

	// Fall back to new/: move to cur/ with the requested flags.
	newPath := filepath.Join(path, "new", uid)
	if _, statErr := os.Stat(newPath); statErr == nil {
		return moveNewToCurWithFlags(path, uid, mdFlags)
	}

	return errors.ErrMessageNotFound
}

// CopyMessage implements msgstore.FolderStore.
func (s *MaildirStore) CopyMessage(ctx context.Context, mailbox string, srcFolder string, uid string, destFolder string) (string, error) {
	srcPath, err := s.folderOrInboxPath(mailbox, srcFolder)
	if err != nil {
		return "", err
	}
	destPath, err := s.folderOrInboxPath(mailbox, destFolder)
	if err != nil {
		return "", err
	}

	// Ensure destination exists.
	destDir := maildir.Dir(destPath)
	if err := os.MkdirAll(destPath, 0700); err != nil {
		return "", err
	}
	if err := destDir.Init(); err != nil && !os.IsExist(err) {
		return "", err
	}

	srcDir := maildir.Dir(srcPath)

	// Try cur/ first. CopyTo places the copy in cur/ and returns the new Message.
	msg, err := srcDir.MessageByKey(uid)
	if err == nil {
		newMsg, err := msg.CopyTo(destDir)
		if err != nil {
			return "", err
		}
		return newMsg.Key(), nil
	}

	// Fall back: source is in new/. Read and deliver to destination's new/.
	newSrcPath := filepath.Join(srcPath, "new", uid)
	if _, statErr := os.Stat(newSrcPath); statErr != nil {
		return "", errors.ErrMessageNotFound
	}

	srcFile, err := os.Open(newSrcPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = srcFile.Close() }()

	// Snapshot new/ in destination before delivery.
	destNewDir := filepath.Join(destPath, "new")
	beforeKeys, err := maildirNewKeys(destNewDir)
	if err != nil {
		return "", err
	}

	delivery, err := maildir.NewDelivery(destPath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(delivery, srcFile); err != nil {
		_ = delivery.Abort()
		return "", err
	}
	if err := delivery.Close(); err != nil {
		return "", err
	}

	return maildirNewKey(destNewDir, beforeKeys)
}

// UIDValidity implements msgstore.FolderStore.
// Returns a stable hash of the folder's base name. For a persistent
// implementation, see issue #9.
func (s *MaildirStore) UIDValidity(ctx context.Context, mailbox string, folder string) (uint32, error) {
	var name string
	if strings.EqualFold(folder, "INBOX") {
		path, err := s.mailboxPath(mailbox)
		if err != nil {
			return 0, err
		}
		name = filepath.Base(path)
	} else {
		name = folder
	}
	// Strip any maildir++ flag suffix if present.
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	h := fnv.New32a()
	h.Write([]byte(name))
	v := h.Sum32()
	if v == 0 {
		return 1, nil
	}
	return v, nil
}

// Compile-time interface verification.
var _ msgstore.MsgStore = (*MaildirStore)(nil)
var _ msgstore.FolderStore = (*MaildirStore)(nil)
