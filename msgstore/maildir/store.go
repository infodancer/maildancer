package maildir

import (
	"bytes"
	"context"
	"io"
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

	// deleted tracks messages marked for deletion per mailbox.
	deletedMu sync.Mutex
	deleted   map[string]map[string]bool // mailbox -> uid -> deleted
}

// NewStore creates a new MaildirStore with the given base path.
// The optional maildirSubdir specifies a subdirectory under each mailbox
// (e.g., "Maildir" for paths like users/testuser/Maildir/).
func NewStore(basePath string, maildirSubdir string) *MaildirStore {
	return &MaildirStore{
		basePath:      basePath,
		maildirSubdir: maildirSubdir,
		deleted:       make(map[string]map[string]bool),
	}
}

// mailboxPath returns the filesystem path for a mailbox.
// Returns an error if the resulting path would escape the base directory.
func (s *MaildirStore) mailboxPath(mailbox string) (string, error) {
	// Build the candidate path
	var candidate string
	if s.maildirSubdir != "" {
		candidate = filepath.Join(s.basePath, mailbox, s.maildirSubdir)
	} else {
		candidate = filepath.Join(s.basePath, mailbox)
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
		dir, err := s.ensureMaildir(recipient)
		if err != nil {
			lastErr = err
			continue
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
func (s *MaildirStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	path, err := s.mailboxPath(mailbox)
	if err != nil {
		return nil, err
	}

	// Check if maildir exists
	curPath := filepath.Join(path, "cur")
	if _, err := os.Stat(curPath); os.IsNotExist(err) {
		return nil, errors.ErrMailboxNotFound
	}

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
		if s.isDeleted(mailbox, key) {
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

	dir := maildir.Dir(path)
	msg, err := dir.MessageByKey(uid)
	if err != nil {
		return nil, err
	}
	return msg.Open()
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

	dir := maildir.Dir(path)

	var lastErr error
	for uid := range deletedUIDs {
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

func (s *MaildirStore) isDeleted(mailbox, uid string) bool {
	s.deletedMu.Lock()
	defer s.deletedMu.Unlock()

	if s.deleted[mailbox] == nil {
		return false
	}
	return s.deleted[mailbox][uid]
}

// Compile-time interface verification.
var _ msgstore.MsgStore = (*MaildirStore)(nil)
