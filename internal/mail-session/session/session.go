// Package session manages the per-connection mailbox state for mail-session.
package session

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	mserrors "github.com/infodancer/maildancer/internal/mail-session/errors"
	"github.com/infodancer/maildancer/msgstore"
)

// flagDeleted is the IMAP \Deleted flag as stored in the msgstore flags slice.
const flagDeleted = "\\Deleted"

// Session holds the state for a single mail-session connection:
// the selected mailbox, the cached message list, and pending deletion marks.
type Session struct {
	store          msgstore.MessageStore
	folderStore    msgstore.FolderStore // nil if the store does not support folders
	mailbox        string               // user identity set by MAILBOX; used in all store calls
	selectedFolder string               // currently selected folder; "" = root (POP3 compat)
	msgs           []msgstore.MessageInfo
	deleted        map[string]struct{} // POP3 pending-deletion marks (not used in IMAP path)
}

// New returns a Session backed by the given MessageStore.
// If the store also implements FolderStore the folder API is available.
func New(store msgstore.MessageStore) *Session {
	fs, _ := store.(msgstore.FolderStore)
	return &Session{
		store:       store,
		folderStore: fs,
		deleted:     make(map[string]struct{}),
	}
}

// Open selects the root mailbox (INBOX equivalent) and caches its message list.
// Used by the POP3 path; MAILBOX command calls this.
func (s *Session) Open(ctx context.Context, mailbox string) error {
	msgs, err := s.store.List(ctx, mailbox)
	if err != nil {
		return fmt.Errorf("open mailbox %q: %w", mailbox, err)
	}
	s.mailbox = mailbox
	s.selectedFolder = ""
	s.msgs = msgs
	s.deleted = make(map[string]struct{})
	return nil
}

// Mailbox returns the currently open mailbox name (user identity).
func (s *Session) Mailbox() string {
	return s.mailbox
}

// List returns the cached message metadata for the currently selected folder.
func (s *Session) List() []msgstore.MessageInfo {
	return s.msgs
}

// Stat returns the count and total byte size of all messages in the cache.
func (s *Session) Stat() (count int, totalBytes int64) {
	for i := range s.msgs {
		totalBytes += s.msgs[i].Size
	}
	return len(s.msgs), totalBytes
}

// GetUID finds a message by UID in the cache. Returns ErrMessageNotFound if absent.
func (s *Session) GetUID(uid string) (*msgstore.MessageInfo, error) {
	for i := range s.msgs {
		if s.msgs[i].UID == uid {
			return &s.msgs[i], nil
		}
	}
	return nil, mserrors.ErrMessageNotFound
}

// Retrieve returns the content of a message by UID from the currently selected folder.
// Routes to the correct store method depending on selectedFolder.
func (s *Session) Retrieve(ctx context.Context, uid string) (io.ReadCloser, error) {
	if s.selectedFolder == "" || strings.EqualFold(s.selectedFolder, "INBOX") {
		return s.store.Retrieve(ctx, s.mailbox, uid)
	}
	if s.folderStore == nil {
		return nil, fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.RetrieveFromFolder(ctx, s.mailbox, s.selectedFolder, uid)
}

// Delete marks a UID for deletion (POP3 path). Returns ErrMessageNotFound or ErrAlreadyDeleted.
func (s *Session) Delete(uid string) error {
	if _, err := s.GetUID(uid); err != nil {
		return err
	}
	if _, marked := s.deleted[uid]; marked {
		return mserrors.ErrAlreadyDeleted
	}
	s.deleted[uid] = struct{}{}
	return nil
}

// Undelete clears a deletion mark (POP3 path). Returns ErrMessageNotFound or ErrNotDeleted.
func (s *Session) Undelete(uid string) error {
	if _, err := s.GetUID(uid); err != nil {
		return err
	}
	if _, marked := s.deleted[uid]; !marked {
		return mserrors.ErrNotDeleted
	}
	delete(s.deleted, uid)
	return nil
}

// Commit calls store.Delete for each POP3-marked UID, then store.Expunge.
func (s *Session) Commit(ctx context.Context) error {
	for uid := range s.deleted {
		if err := s.store.Delete(ctx, s.mailbox, uid); err != nil {
			return fmt.Errorf("delete %q: %w", uid, err)
		}
	}
	if len(s.deleted) > 0 {
		if err := s.store.Expunge(ctx, s.mailbox); err != nil {
			return fmt.Errorf("expunge: %w", err)
		}
	}
	return nil
}

// --- IMAP-path methods ---

// Select selects a named folder and caches its message list.
// "INBOX" routes to store.List; any other name requires FolderStore.
// Returns the cached message list so callers can format the response immediately.
func (s *Session) Select(ctx context.Context, folder string) ([]msgstore.MessageInfo, error) {
	var msgs []msgstore.MessageInfo
	var err error

	if strings.EqualFold(folder, "INBOX") {
		msgs, err = s.store.List(ctx, s.mailbox)
	} else {
		if s.folderStore == nil {
			return nil, fmt.Errorf("folder operations not supported")
		}
		msgs, err = s.folderStore.ListInFolder(ctx, s.mailbox, folder)
	}
	if err != nil {
		return nil, fmt.Errorf("select %q: %w", folder, err)
	}

	s.selectedFolder = folder
	s.msgs = msgs
	return msgs, nil
}

// Folders lists all non-INBOX folders for the current mailbox.
func (s *Session) Folders(ctx context.Context) ([]string, error) {
	if s.folderStore == nil {
		return nil, fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.ListFolders(ctx, s.mailbox)
}

// UIDValidity returns the UIDValidity value for the named folder.
func (s *Session) UIDValidity(ctx context.Context, folder string) (uint32, error) {
	if s.folderStore == nil {
		return 0, fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.UIDValidity(ctx, s.mailbox, folder)
}

// CreateFolder creates a new folder within the current mailbox.
func (s *Session) CreateFolder(ctx context.Context, name string) error {
	if s.folderStore == nil {
		return fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.CreateFolder(ctx, s.mailbox, name)
}

// DeleteFolder removes a folder and all its messages.
func (s *Session) DeleteFolder(ctx context.Context, name string) error {
	if s.folderStore == nil {
		return fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.DeleteFolder(ctx, s.mailbox, name)
}

// RenameFolder renames a folder within the current mailbox.
func (s *Session) RenameFolder(ctx context.Context, oldName, newName string) error {
	if s.folderStore == nil {
		return fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.RenameFolder(ctx, s.mailbox, oldName, newName)
}

// SetFlags replaces the complete flag set on a message in the currently selected folder.
// The in-memory cache is updated to reflect the change.
func (s *Session) SetFlags(ctx context.Context, uid string, flags []string) error {
	if s.folderStore == nil {
		return fmt.Errorf("folder operations not supported")
	}
	folder := s.selectedFolder
	if folder == "" {
		folder = "INBOX"
	}
	if err := s.folderStore.SetFlagsInFolder(ctx, s.mailbox, folder, uid, flags); err != nil {
		return err
	}
	// Keep in-memory cache consistent.
	for i, m := range s.msgs {
		if m.UID == uid {
			s.msgs[i].Flags = flags
			break
		}
	}
	return nil
}

// Expunge permanently removes all messages in the currently selected folder that
// carry the \Deleted flag. Returns the msgstore UIDs of the expelled messages.
// The session remains open after expunge (unlike POP3 COMMIT).
func (s *Session) Expunge(ctx context.Context) ([]string, error) {
	var expelled []string

	for _, m := range s.msgs {
		if hasFlag(m.Flags, flagDeleted) {
			folder := s.selectedFolder
			if folder == "" || strings.EqualFold(folder, "INBOX") {
				if err := s.store.Delete(ctx, s.mailbox, m.UID); err != nil {
					return nil, fmt.Errorf("delete %q: %w", m.UID, err)
				}
			} else {
				if s.folderStore == nil {
					return nil, fmt.Errorf("folder operations not supported")
				}
				if err := s.folderStore.DeleteInFolder(ctx, s.mailbox, folder, m.UID); err != nil {
					return nil, fmt.Errorf("delete %q in %q: %w", m.UID, folder, err)
				}
			}
			expelled = append(expelled, m.UID)
		}
	}

	if len(expelled) > 0 {
		folder := s.selectedFolder
		if folder == "" || strings.EqualFold(folder, "INBOX") {
			if err := s.store.Expunge(ctx, s.mailbox); err != nil {
				return nil, fmt.Errorf("expunge: %w", err)
			}
		} else {
			if err := s.folderStore.ExpungeFolder(ctx, s.mailbox, folder); err != nil {
				return nil, fmt.Errorf("expunge folder %q: %w", folder, err)
			}
		}
		// Reload cache to reflect the deletions.
		msgs, err := s.Select(ctx, folder)
		if err != nil {
			return nil, err
		}
		s.msgs = msgs
	}

	return expelled, nil
}

// AppendMessage stores a new message in the named folder with the given flags and date.
// Returns the assigned msgstore UID.
func (s *Session) AppendMessage(ctx context.Context, folder string, data []byte, flags []string, date time.Time) (string, error) {
	if s.folderStore == nil {
		return "", fmt.Errorf("folder operations not supported")
	}
	uid, err := s.folderStore.AppendToFolder(ctx, s.mailbox, folder, strings.NewReader(string(data)), flags, date)
	if err != nil {
		return "", fmt.Errorf("append to %q: %w", folder, err)
	}
	return uid, nil
}

// CopyMessage copies the message with the given UID from the currently selected
// folder to destFolder. Returns the new UID in the destination.
func (s *Session) CopyMessage(ctx context.Context, uid, destFolder string) (string, error) {
	if s.folderStore == nil {
		return "", fmt.Errorf("folder operations not supported")
	}
	folder := s.selectedFolder
	if folder == "" {
		folder = "INBOX"
	}
	newUID, err := s.folderStore.CopyMessage(ctx, s.mailbox, folder, uid, destFolder)
	if err != nil {
		return "", fmt.Errorf("copy %q from %q to %q: %w", uid, folder, destFolder, err)
	}
	return newUID, nil
}

// RetrieveFrom returns the content of a message by UID from an explicit folder,
// ignoring the currently selected folder. Used to fetch message bytes for rspamd
// learning before a move operation changes the message's location.
func (s *Session) RetrieveFrom(ctx context.Context, folder, uid string) (io.ReadCloser, error) {
	if folder == "" || strings.EqualFold(folder, "INBOX") {
		return s.store.Retrieve(ctx, s.mailbox, uid)
	}
	if s.folderStore == nil {
		return nil, fmt.Errorf("folder operations not supported")
	}
	return s.folderStore.RetrieveFromFolder(ctx, s.mailbox, folder, uid)
}

// MoveMessage copies a message from srcFolder to destFolder, then deletes and
// expunges it from the source. Returns the new UID in the destination.
// srcFolder "" is treated as INBOX.
func (s *Session) MoveMessage(ctx context.Context, uid, srcFolder, destFolder string) (string, error) {
	if s.folderStore == nil {
		return "", fmt.Errorf("folder operations not supported")
	}
	if srcFolder == "" {
		srcFolder = "INBOX"
	}

	newUID, err := s.folderStore.CopyMessage(ctx, s.mailbox, srcFolder, uid, destFolder)
	if err != nil {
		return "", fmt.Errorf("copy %q from %q to %q: %w", uid, srcFolder, destFolder, err)
	}

	if strings.EqualFold(srcFolder, "INBOX") {
		if err := s.store.Delete(ctx, s.mailbox, uid); err != nil {
			return "", fmt.Errorf("delete %q from INBOX: %w", uid, err)
		}
		if err := s.store.Expunge(ctx, s.mailbox); err != nil {
			return "", fmt.Errorf("expunge INBOX: %w", err)
		}
	} else {
		if err := s.folderStore.DeleteInFolder(ctx, s.mailbox, srcFolder, uid); err != nil {
			return "", fmt.Errorf("delete %q from %q: %w", uid, srcFolder, err)
		}
		if err := s.folderStore.ExpungeFolder(ctx, s.mailbox, srcFolder); err != nil {
			return "", fmt.Errorf("expunge %q: %w", srcFolder, err)
		}
	}

	return newUID, nil
}

// hasFlag reports whether flags contains the given flag string.
func hasFlag(flags []string, flag string) bool {
	return slices.Contains(flags, flag)
}
