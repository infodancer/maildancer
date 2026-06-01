package maildir

import (
	"bytes"
	"context"
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

	// deleted tracks messages marked for deletion by uint32 UID.
	// Keys are mailbox names for INBOX, or composite keys for folders.
	deletedMu sync.Mutex
	deleted   map[string]map[uint32]bool // deletion key -> uid -> deleted

	// uidlistCache caches parsed uidlists per folder path.
	// Invalidated on mutating operations (Deliver, Append, Copy, Expunge).
	uidlistMu    sync.Mutex
	uidlistCache map[string]*uidList // folder path -> uidlist
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
		deleted:       make(map[string]map[uint32]bool),
		uidlistCache:  make(map[string]*uidList),
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

// expandMailbox resolves a mailbox identifier to a relative filesystem path.
//
// By default (no template), the domain part is stripped: "alice@example.com"
// becomes "alice". This matches the production layout where each domain has
// its own store rooted at a domain-specific base_path, so the localpart is
// the correct key into that store regardless of whether the caller is smtpd
// (which has the full address) or pop3d (which has already split on domain).
//
// An explicit pathTemplate overrides the default:
//   - {localpart}  — same as default; domain stripped
//   - {domain}     — use domain only
//   - {email}      — use the full address as-is
//   - arbitrary combinations, e.g. "{domain}/users/{localpart}"
func (s *MaildirStore) expandMailbox(mailbox string) string {
	localpart, domain := splitEmail(mailbox)
	if s.pathTemplate == "" {
		return localpart
	}
	result := s.pathTemplate
	result = strings.ReplaceAll(result, "{domain}", domain)
	result = strings.ReplaceAll(result, "{localpart}", localpart)
	result = strings.ReplaceAll(result, "{email}", mailbox)
	return result
}

// mailboxPath returns the filesystem path for a mailbox.
// Returns an error if the resulting path would escape the base directory.
func (s *MaildirStore) mailboxPath(mailbox string) (string, error) {
	// Apply path template transformation (strips domain by default)
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
		// Create default folders for newly provisioned mailboxes.
		if err := s.EnsureDefaultFolders(context.Background(), mailbox); err != nil {
			slog.Warn("failed to create default folders",
				slog.String("mailbox", mailbox),
				slog.String("error", err.Error()),
			)
		}
	}

	return dir, nil
}

// EnsureDefaultFolders creates all default folders for a mailbox.
// Folders that already exist are silently skipped. Safe to call repeatedly.
func (s *MaildirStore) EnsureDefaultFolders(ctx context.Context, mailbox string) error {
	for _, spec := range msgstore.DefaultFolders {
		if err := s.CreateFolder(ctx, mailbox, spec.Name); err != nil {
			if err == errors.ErrFolderExists {
				continue
			}
			return err
		}
	}
	return nil
}

// --- Common helpers ---

// listDir returns message metadata for all non-deleted messages in the given maildir path.
// deletionKey identifies which set of soft-deleted messages to filter out.
// Messages are returned sorted by UID ascending with persistent UIDs from .uidlist.
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

	// Load/reconcile uidlist against current cur/ contents.
	keys, err := curDirKeys(path)
	if err != nil {
		return nil, err
	}

	lock, err := lockUIDList(path)
	if err != nil {
		return nil, err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	unlockUIDList(lock)
	if err != nil {
		return nil, err
	}

	// Cache the uidlist for subsequent Retrieve/Delete calls.
	s.cacheUIDList(path, ul)

	// Build a map from key to go-maildir Message for flag/stat lookup.
	allMsgs, err := dir.Messages()
	if err != nil {
		return nil, err
	}
	msgByKey := make(map[string]*maildir.Message, len(allMsgs))
	for _, msg := range allMsgs {
		msgByKey[msg.Key()] = msg
	}

	// Walk uidlist entries (sorted by UID ascending) to build results.
	var messages []msgstore.MessageInfo
	for _, entry := range ul.entries {
		if s.isDeleted(deletionKey, entry.uid) {
			continue
		}

		msg, ok := msgByKey[entry.key]
		if !ok {
			continue // Key in uidlist but not in cur/; already reconciled
		}

		filename := msg.Filename()
		fi, err := os.Stat(filename)
		if err != nil {
			continue
		}

		flags := msg.Flags()
		var flagStrings []string
		if recentKeys[entry.key] {
			flagStrings = append(flagStrings, "\\Recent")
		}
		flagStrings = append(flagStrings, convertFlags(flags)...)

		messages = append(messages, msgstore.MessageInfo{
			UID:          entry.uid,
			Key:          entry.key,
			Size:         fi.Size(),
			Flags:        flagStrings,
			InternalDate: fi.ModTime(),
		})
	}

	return messages, nil
}

// cacheUIDList stores a uidlist in the per-folder cache.
func (s *MaildirStore) cacheUIDList(path string, ul *uidList) {
	s.uidlistMu.Lock()
	s.uidlistCache[path] = ul
	s.uidlistMu.Unlock()
}

// invalidateUIDListCache removes a cached uidlist for the given path.
func (s *MaildirStore) invalidateUIDListCache(path string) {
	s.uidlistMu.Lock()
	delete(s.uidlistCache, path)
	s.uidlistMu.Unlock()
}

// lookupKey resolves a uint32 UID to its Maildir key using the cache or disk.
func (s *MaildirStore) lookupKey(path string, uid uint32) (string, error) {
	// Try cache first.
	s.uidlistMu.Lock()
	if ul, ok := s.uidlistCache[path]; ok {
		s.uidlistMu.Unlock()
		if key, ok := ul.uidToKey[uid]; ok {
			return key, nil
		}
		return "", errors.ErrMessageNotFound
	}
	s.uidlistMu.Unlock()

	// Cache miss — load from disk.
	lock, err := lockUIDList(path)
	if err != nil {
		return "", err
	}
	keys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return "", err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	unlockUIDList(lock)
	if err != nil {
		return "", err
	}
	s.cacheUIDList(path, ul)

	if key, ok := ul.uidToKey[uid]; ok {
		return key, nil
	}
	return "", errors.ErrMessageNotFound
}

// retrieveFromDir retrieves a single message from the given maildir path by Maildir key.
func (s *MaildirStore) retrieveFromDir(path string, key string) (io.ReadCloser, error) {
	dir := maildir.Dir(path)
	msg, err := dir.MessageByKey(key)
	if err != nil {
		return nil, err
	}
	return msg.Open()
}

// removeMessages permanently removes the specified messages from a maildir by key.
func (s *MaildirStore) removeMessages(path string, keys map[string]bool) error {
	dir := maildir.Dir(path)
	var lastErr error
	for key := range keys {
		msg, err := dir.MessageByKey(key)
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

func (s *MaildirStore) isDeleted(key string, uid uint32) bool {
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
func (s *MaildirStore) Retrieve(ctx context.Context, mailbox string, uid uint32) (io.ReadCloser, error) {
	if s.isDeleted(mailbox, uid) {
		return nil, errors.ErrMessageDeleted
	}

	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return nil, err
	}

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrMailboxNotFound
	}

	key, err := s.lookupKey(path, uid)
	if err != nil {
		return nil, err
	}

	return s.retrieveFromDir(path, key)
}

// Delete implements msgstore.MessageStore.
func (s *MaildirStore) Delete(ctx context.Context, mailbox string, uid uint32) error {
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[mailbox] == nil {
		s.deleted[mailbox] = make(map[uint32]bool)
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

	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return errors.ErrMailboxNotFound
	}

	// Resolve uint32 UIDs to Maildir keys for removal.
	lock, err := lockUIDList(path)
	if err != nil {
		return err
	}
	keys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	if err != nil {
		unlockUIDList(lock)
		return err
	}

	keysToRemove := make(map[string]bool)
	for uid := range deletedUIDs {
		if key, ok := ul.uidToKey[uid]; ok {
			keysToRemove[key] = true
		}
	}

	if err := s.removeMessages(path, keysToRemove); err != nil {
		unlockUIDList(lock)
		return err
	}

	// Reconcile uidlist after removal (removes entries for deleted keys).
	remainingKeys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return err
	}
	ul.reconcile(remainingKeys)
	err = ul.write(path)
	unlockUIDList(lock)

	s.invalidateUIDListCache(path)
	return err
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
func (s *MaildirStore) RetrieveFromFolder(ctx context.Context, mailbox string, folder string, uid uint32) (io.ReadCloser, error) {
	delKey := folderDeletionKey(mailbox, folder)
	if s.isDeleted(delKey, uid) {
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

	key, err := s.lookupKey(path, uid)
	if err != nil {
		return nil, err
	}

	return s.retrieveFromDir(path, key)
}

// DeleteInFolder implements msgstore.FolderStore.
func (s *MaildirStore) DeleteInFolder(ctx context.Context, mailbox string, folder string, uid uint32) error {
	if err := validateFolderName(folder); err != nil {
		return err
	}

	delKey := folderDeletionKey(mailbox, folder)
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[delKey] == nil {
		s.deleted[delKey] = make(map[uint32]bool)
	}
	s.deleted[delKey][uid] = true
	return nil
}

// ExpungeFolder implements msgstore.FolderStore.
func (s *MaildirStore) ExpungeFolder(ctx context.Context, mailbox string, folder string) error {
	delKey := folderDeletionKey(mailbox, folder)

	s.deletedMu.Lock()
	deletedUIDs := s.deleted[delKey]
	delete(s.deleted, delKey)
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

	// Resolve uint32 UIDs to Maildir keys for removal.
	lock, err := lockUIDList(path)
	if err != nil {
		return err
	}
	keys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	if err != nil {
		unlockUIDList(lock)
		return err
	}

	keysToRemove := make(map[string]bool)
	for uid := range deletedUIDs {
		if key, ok := ul.uidToKey[uid]; ok {
			keysToRemove[key] = true
		}
	}

	if err := s.removeMessages(path, keysToRemove); err != nil {
		unlockUIDList(lock)
		return err
	}

	// Reconcile uidlist after removal.
	remainingKeys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return err
	}
	ul.reconcile(remainingKeys)
	err = ul.write(path)
	unlockUIDList(lock)

	s.invalidateUIDListCache(path)
	return err
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
func (s *MaildirStore) AppendToFolder(ctx context.Context, mailbox string, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return 0, err
	}

	dir := maildir.Dir(path)
	if err := os.MkdirAll(path, 0700); err != nil {
		return 0, err
	}
	if err := dir.Init(); err != nil && !os.IsExist(err) {
		return 0, err
	}

	// Snapshot new/ before delivery to identify the resulting key.
	newDir := filepath.Join(path, "new")
	beforeKeys, err := maildirNewKeys(newDir)
	if err != nil {
		return 0, err
	}

	delivery, err := maildir.NewDelivery(path)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(delivery, r); err != nil {
		_ = delivery.Abort()
		return 0, err
	}
	if err := delivery.Close(); err != nil {
		return 0, err
	}

	// Find the newly added key in new/.
	key, err := maildirNewKey(newDir, beforeKeys)
	if err != nil {
		return 0, err
	}

	// Move from new/ to cur/ with the requested flags. IMAP APPEND messages
	// are explicitly placed by the client and must be immediately accessible.
	if err := moveNewToCurWithFlags(path, key, convertFlagsFromIMAP(flags)); err != nil {
		return 0, err
	}

	// Assign a UID in the uidlist.
	lock, err := lockUIDList(path)
	if err != nil {
		return 0, err
	}
	curKeys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return 0, err
	}
	ul, err := loadOrBootstrapUIDList(path, curKeys)
	unlockUIDList(lock)
	if err != nil {
		return 0, err
	}

	s.invalidateUIDListCache(path)

	uid, ok := ul.keyToUID[key]
	if !ok {
		return 0, errors.ErrMessageNotFound
	}
	return uid, nil
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
func (s *MaildirStore) SetFlagsInFolder(ctx context.Context, mailbox string, folder string, uid uint32, flags []string) error {
	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return err
	}

	key, err := s.lookupKey(path, uid)
	if err != nil {
		return err
	}

	mdFlags := convertFlagsFromIMAP(flags)
	dir := maildir.Dir(path)

	// Try cur/ first (most messages live here).
	msg, err := dir.MessageByKey(key)
	if err == nil {
		return msg.SetFlags(mdFlags)
	}

	// Fall back to new/: move to cur/ with the requested flags.
	newPath := filepath.Join(path, "new", key)
	if _, statErr := os.Stat(newPath); statErr == nil {
		return moveNewToCurWithFlags(path, key, mdFlags)
	}

	return errors.ErrMessageNotFound
}

// CopyMessage implements msgstore.FolderStore.
func (s *MaildirStore) CopyMessage(ctx context.Context, mailbox string, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	srcPath, err := s.folderOrInboxPath(mailbox, srcFolder)
	if err != nil {
		return 0, err
	}
	destPath, err := s.folderOrInboxPath(mailbox, destFolder)
	if err != nil {
		return 0, err
	}

	// Resolve source UID to Maildir key.
	srcKey, err := s.lookupKey(srcPath, uid)
	if err != nil {
		return 0, err
	}

	// Ensure destination exists.
	destDir := maildir.Dir(destPath)
	if err := os.MkdirAll(destPath, 0700); err != nil {
		return 0, err
	}
	if err := destDir.Init(); err != nil && !os.IsExist(err) {
		return 0, err
	}

	srcDir := maildir.Dir(srcPath)

	// Try cur/ first. CopyTo places the copy in cur/ and returns the new Message.
	msg, err := srcDir.MessageByKey(srcKey)
	if err == nil {
		_, err := msg.CopyTo(destDir)
		if err != nil {
			return 0, err
		}
	} else {
		// Fall back: source is in new/. Read and deliver to destination's new/.
		newSrcPath := filepath.Join(srcPath, "new", srcKey)
		if _, statErr := os.Stat(newSrcPath); statErr != nil {
			return 0, errors.ErrMessageNotFound
		}

		srcFile, err := os.Open(newSrcPath)
		if err != nil {
			return 0, err
		}
		defer func() { _ = srcFile.Close() }()

		delivery, err := maildir.NewDelivery(destPath)
		if err != nil {
			return 0, err
		}
		if _, err := io.Copy(delivery, srcFile); err != nil {
			_ = delivery.Abort()
			return 0, err
		}
		if err := delivery.Close(); err != nil {
			return 0, err
		}
	}

	// Assign a UID in the destination uidlist.
	lock, err := lockUIDList(destPath)
	if err != nil {
		return 0, err
	}
	destKeys, err := curDirKeys(destPath)
	if err != nil {
		unlockUIDList(lock)
		return 0, err
	}
	ul, err := loadOrBootstrapUIDList(destPath, destKeys)
	unlockUIDList(lock)
	if err != nil {
		return 0, err
	}

	s.invalidateUIDListCache(destPath)

	// The new message's key will be the highest UID (just assigned by reconcile).
	// Return uidNext - 1 as the newly assigned UID.
	newUID := ul.uidNext - 1
	return newUID, nil
}

// UIDValidity implements msgstore.FolderStore.
// Returns the persistent UIDValidity from the .uidlist file.
// If the file does not exist, bootstraps a new uidlist.
func (s *MaildirStore) UIDValidity(ctx context.Context, mailbox string, folder string) (uint32, error) {
	// Ensure the maildir exists so we can create the lock file.
	if strings.EqualFold(folder, "INBOX") {
		if _, err := s.ensureMaildir(mailbox); err != nil {
			return 0, err
		}
	} else {
		if _, err := s.ensureFolderMaildir(mailbox, folder); err != nil {
			return 0, err
		}
	}

	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return 0, err
	}

	lock, err := lockUIDList(path)
	if err != nil {
		return 0, err
	}
	keys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return 0, err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	unlockUIDList(lock)
	if err != nil {
		return 0, err
	}

	return ul.uidValidity, nil
}

// UIDNext implements msgstore.FolderStore.
// Returns the next UID that will be assigned in the folder.
func (s *MaildirStore) UIDNext(ctx context.Context, mailbox string, folder string) (uint32, error) {
	// Ensure the maildir exists so we can create the lock file.
	if strings.EqualFold(folder, "INBOX") {
		if _, err := s.ensureMaildir(mailbox); err != nil {
			return 0, err
		}
	} else {
		if _, err := s.ensureFolderMaildir(mailbox, folder); err != nil {
			return 0, err
		}
	}

	path, err := s.folderOrInboxPath(mailbox, folder)
	if err != nil {
		return 0, err
	}

	lock, err := lockUIDList(path)
	if err != nil {
		return 0, err
	}
	keys, err := curDirKeys(path)
	if err != nil {
		unlockUIDList(lock)
		return 0, err
	}
	ul, err := loadOrBootstrapUIDList(path, keys)
	unlockUIDList(lock)
	if err != nil {
		return 0, err
	}

	return ul.uidNext, nil
}

// Compile-time interface verification.
var _ msgstore.MsgStore = (*MaildirStore)(nil)
var _ msgstore.FolderStore = (*MaildirStore)(nil)
