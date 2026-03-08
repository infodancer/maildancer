package backend

import (
	"context"
	"io"
	"time"

	"github.com/infodancer/maildancer/msgstore"
)

// Compile-time interface assertions.
var (
	_ msgstore.MessageStore = (*sessionManagerStore)(nil)
	_ msgstore.FolderStore  = (*sessionManagerStore)(nil)
	_ mover                 = (*sessionManagerStore)(nil)
	_ rescanner             = (*sessionManagerStore)(nil)
	_ io.Closer             = (*sessionManagerStore)(nil)
)

// sessionManagerStore adapts a SessionManagerClient into msgstore.MessageStore,
// msgstore.FolderStore, mover, and rescanner interfaces. All operations are
// proxied through the session-manager using the session token obtained during Login.
// Closing the store calls Logout.
type sessionManagerStore struct {
	client         *SessionManagerClient
	token          string
	selectedFolder string // tracks folder for Rescan; set by ListInFolder
}

// newSessionManagerStore creates a store backed by the given client and session token.
func newSessionManagerStore(client *SessionManagerClient, token string) *sessionManagerStore {
	return &sessionManagerStore{client: client, token: token}
}

// --- msgstore.MessageStore ---

func (s *sessionManagerStore) List(ctx context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return s.ListInFolder(ctx, "", "INBOX")
}

func (s *sessionManagerStore) Retrieve(ctx context.Context, _ string, uid string) (io.ReadCloser, error) {
	return s.RetrieveFromFolder(ctx, "", "INBOX", uid)
}

func (s *sessionManagerStore) Delete(ctx context.Context, _ string, uid string) error {
	return s.client.DeleteMessage(ctx, s.token, "INBOX", uid)
}

func (s *sessionManagerStore) Expunge(ctx context.Context, _ string) error {
	return s.client.ExpungeMailbox(ctx, s.token, "INBOX")
}

func (s *sessionManagerStore) Stat(ctx context.Context, _ string) (int, int64, error) {
	count, totalBytes, err := s.client.StatMailbox(ctx, s.token, "INBOX")
	if err != nil {
		return 0, 0, err
	}
	return int(count), totalBytes, nil
}

// --- msgstore.FolderStore ---

func (s *sessionManagerStore) CreateFolder(ctx context.Context, _ string, folder string) error {
	return s.client.CreateFolder(ctx, s.token, folder)
}

func (s *sessionManagerStore) ListFolders(ctx context.Context, _ string) ([]string, error) {
	return s.client.ListFolders(ctx, s.token)
}

func (s *sessionManagerStore) DeleteFolder(ctx context.Context, _ string, folder string) error {
	return s.client.DeleteFolder(ctx, s.token, folder)
}

func (s *sessionManagerStore) ListInFolder(ctx context.Context, _ string, folder string) ([]msgstore.MessageInfo, error) {
	s.selectedFolder = folder
	msgs, err := s.client.ListMessages(ctx, s.token, folder)
	if err != nil {
		return nil, err
	}
	result := make([]msgstore.MessageInfo, len(msgs))
	for i, m := range msgs {
		result[i] = msgstore.MessageInfo{
			UID:   m.Uid,
			Size:  m.Size,
			Flags: m.Flags,
		}
	}
	return result, nil
}

func (s *sessionManagerStore) StatFolder(ctx context.Context, _ string, folder string) (int, int64, error) {
	count, totalBytes, err := s.client.StatMailbox(ctx, s.token, folder)
	if err != nil {
		return 0, 0, err
	}
	return int(count), totalBytes, nil
}

func (s *sessionManagerStore) RetrieveFromFolder(ctx context.Context, _ string, folder string, uid string) (io.ReadCloser, error) {
	return s.client.FetchMessage(ctx, s.token, folder, uid)
}

func (s *sessionManagerStore) DeleteInFolder(ctx context.Context, _ string, folder string, uid string) error {
	return s.client.DeleteMessage(ctx, s.token, folder, uid)
}

func (s *sessionManagerStore) ExpungeFolder(ctx context.Context, _ string, folder string) error {
	return s.client.ExpungeMailbox(ctx, s.token, folder)
}

func (s *sessionManagerStore) DeliverToFolder(ctx context.Context, _ string, folder string, message io.Reader) error {
	_, err := s.client.AppendMessage(ctx, s.token, folder, message, nil, time.Now())
	return err
}

func (s *sessionManagerStore) RenameFolder(ctx context.Context, _ string, oldName string, newName string) error {
	return s.client.RenameFolder(ctx, s.token, oldName, newName)
}

func (s *sessionManagerStore) AppendToFolder(ctx context.Context, _ string, folder string, r io.Reader, flags []string, date time.Time) (string, error) {
	return s.client.AppendMessage(ctx, s.token, folder, r, flags, date)
}

func (s *sessionManagerStore) SetFlagsInFolder(ctx context.Context, _ string, folder string, uid string, flags []string) error {
	return s.client.SetFlags(ctx, s.token, folder, uid, flags)
}

func (s *sessionManagerStore) CopyMessage(ctx context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	return s.client.CopyMessage(ctx, s.token, srcFolder, uid, destFolder)
}

func (s *sessionManagerStore) UIDValidity(ctx context.Context, _ string, folder string) (uint32, error) {
	return s.client.UIDValidity(ctx, s.token, folder)
}

// --- mover ---

func (s *sessionManagerStore) MoveMessage(ctx context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	return s.client.MoveMessage(ctx, s.token, srcFolder, uid, destFolder)
}

// --- rescanner ---

func (s *sessionManagerStore) Rescan() ([]msgstore.MessageInfo, error) {
	folder := s.selectedFolder
	if folder == "" {
		folder = "INBOX"
	}
	msgs, err := s.client.RescanFolder(context.Background(), s.token, folder)
	if err != nil {
		return nil, err
	}
	result := make([]msgstore.MessageInfo, len(msgs))
	for i, m := range msgs {
		result[i] = msgstore.MessageInfo{
			UID:   m.Uid,
			Size:  m.Size,
			Flags: m.Flags,
		}
	}
	return result, nil
}

// --- io.Closer ---

// Close releases the session by calling Logout on the session-manager.
func (s *sessionManagerStore) Close() error {
	return s.client.Logout(context.Background(), s.token)
}
