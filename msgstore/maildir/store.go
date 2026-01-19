package maildir

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

// MaildirStore implements msgstore.MsgStore using the Maildir format.
type MaildirStore struct {
	basePath string

	// deleted tracks messages marked for deletion per mailbox.
	deletedMu sync.Mutex
	deleted   map[string]map[string]bool // mailbox -> uid -> deleted
}

// NewStore creates a new MaildirStore with the given base path.
func NewStore(basePath string) *MaildirStore {
	return &MaildirStore{
		basePath: basePath,
		deleted:  make(map[string]map[string]bool),
	}
}

// mailboxPath returns the filesystem path for a mailbox.
func (s *MaildirStore) mailboxPath(mailbox string) string {
	// Sanitize mailbox name to prevent path traversal
	safe := strings.ReplaceAll(mailbox, "..", "")
	safe = strings.ReplaceAll(safe, "/", "_")
	return filepath.Join(s.basePath, safe)
}

// getMaildir returns a Maildir for the given mailbox, creating it if needed.
func (s *MaildirStore) getMaildir(mailbox string) (*Maildir, error) {
	path := s.mailboxPath(mailbox)
	md := New(path)
	if !md.Exists() {
		if err := md.Create(); err != nil {
			return nil, err
		}
	}
	return md, nil
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
		md, err := s.getMaildir(recipient)
		if err != nil {
			lastErr = err
			continue
		}

		reader := strings.NewReader(string(data))
		if _, err := md.Deliver(reader); err != nil {
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
	path := s.mailboxPath(mailbox)
	md := New(path)
	if !md.Exists() {
		return nil, errors.ErrMailboxNotFound
	}

	var messages []msgstore.MessageInfo

	// List messages in new/
	newFiles, err := md.ListNew()
	if err != nil && err != errors.ErrMaildirNotFound {
		return nil, err
	}
	for _, filename := range newFiles {
		if s.isDeleted(mailbox, filename) {
			continue
		}
		info, err := s.getMessageInfo(path, "new", filename)
		if err != nil {
			continue
		}
		messages = append(messages, info)
	}

	// List messages in cur/
	curFiles, err := md.ListCur()
	if err != nil && err != errors.ErrMaildirNotFound {
		return nil, err
	}
	for _, filename := range curFiles {
		if s.isDeleted(mailbox, filename) {
			continue
		}
		info, err := s.getMessageInfo(path, "cur", filename)
		if err != nil {
			continue
		}
		messages = append(messages, info)
	}

	return messages, nil
}

func (s *MaildirStore) getMessageInfo(basePath, subdir, filename string) (msgstore.MessageInfo, error) {
	path := filepath.Join(basePath, subdir, filename)
	fi, err := os.Stat(path)
	if err != nil {
		return msgstore.MessageInfo{}, err
	}

	// Parse flags from filename (format: unique:2,flags)
	flags := parseFlags(filename)
	if subdir == "new" {
		// Messages in new/ are implicitly unseen
		flags = append(flags, "\\Recent")
	}

	return msgstore.MessageInfo{
		UID:   filename,
		Size:  fi.Size(),
		Flags: flags,
	}, nil
}

// parseFlags extracts flags from a maildir filename.
// Format: unique:2,flags where flags are single characters like S, R, T, D, F
func parseFlags(filename string) []string {
	var flags []string
	if idx := strings.Index(filename, ":2,"); idx != -1 {
		flagStr := filename[idx+3:]
		for _, c := range flagStr {
			switch c {
			case 'S':
				flags = append(flags, "\\Seen")
			case 'R':
				flags = append(flags, "\\Answered")
			case 'T':
				flags = append(flags, "\\Deleted")
			case 'D':
				flags = append(flags, "\\Draft")
			case 'F':
				flags = append(flags, "\\Flagged")
			}
		}
	}
	return flags
}

// Retrieve implements msgstore.MessageStore.
func (s *MaildirStore) Retrieve(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error) {
	if s.isDeleted(mailbox, uid) {
		return nil, errors.ErrMessageDeleted
	}

	path := s.mailboxPath(mailbox)
	md := New(path)
	if !md.Exists() {
		return nil, errors.ErrMailboxNotFound
	}

	return md.Open(uid)
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

	path := s.mailboxPath(mailbox)
	md := New(path)
	if !md.Exists() {
		return errors.ErrMailboxNotFound
	}

	var lastErr error
	for uid := range deletedUIDs {
		if err := md.Remove(uid); err != nil && !os.IsNotExist(err) {
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
