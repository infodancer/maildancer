package backend

import (
	"context"
	"io"
	"time"

	"github.com/infodancer/maildancer/internal/smclient"
	"github.com/infodancer/maildancer/msgstore"
)

// Compile-time interface assertions.
var (
	_ msgstore.MessageStore    = (*sessionManagerStore)(nil)
	_ msgstore.FolderStore     = (*sessionManagerStore)(nil)
	_ msgstore.ContentSearcher = (*sessionManagerStore)(nil)
	_ mover                    = (*sessionManagerStore)(nil)
	_ rescanner                = (*sessionManagerStore)(nil)
	_ io.Closer                = (*sessionManagerStore)(nil)
)

// sessionManagerStore adapts a recovering smclient.Session into
// msgstore.MessageStore, msgstore.FolderStore, mover, and rescanner
// interfaces. All operations are proxied through the session-manager; the
// Session transparently recovers across session-manager restarts (#179).
// Closing the store calls Logout.
type sessionManagerStore struct {
	sess           *smclient.Session
	selectedFolder string // tracks folder for Rescan; set by ListInFolder
}

// newSessionManagerStore creates a store backed by the given recovering session.
func newSessionManagerStore(sess *smclient.Session) *sessionManagerStore {
	return &sessionManagerStore{sess: sess}
}

// --- msgstore.MessageStore ---

func (s *sessionManagerStore) List(ctx context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return s.ListInFolder(ctx, "", "INBOX")
}

func (s *sessionManagerStore) Retrieve(ctx context.Context, _ string, uid uint32) (io.ReadCloser, error) {
	return s.RetrieveFromFolder(ctx, "", "INBOX", uid)
}

func (s *sessionManagerStore) Delete(ctx context.Context, _ string, uid uint32) error {
	return s.sess.DeleteMessage(ctx, "INBOX", uid)
}

func (s *sessionManagerStore) Expunge(ctx context.Context, _ string) error {
	return s.sess.ExpungeMailbox(ctx, "INBOX")
}

func (s *sessionManagerStore) Stat(ctx context.Context, _ string) (int, int64, error) {
	count, totalBytes, err := s.sess.StatMailbox(ctx, "INBOX")
	if err != nil {
		return 0, 0, err
	}
	return int(count), totalBytes, nil
}

// --- msgstore.FolderStore ---

func (s *sessionManagerStore) CreateFolder(ctx context.Context, _ string, folder string) error {
	return s.sess.CreateFolder(ctx, folder)
}

func (s *sessionManagerStore) ListFolders(ctx context.Context, _ string) ([]string, error) {
	return s.sess.ListFolders(ctx)
}

func (s *sessionManagerStore) DeleteFolder(ctx context.Context, _ string, folder string) error {
	return s.sess.DeleteFolder(ctx, folder)
}

func (s *sessionManagerStore) ListInFolder(ctx context.Context, _ string, folder string) ([]msgstore.MessageInfo, error) {
	s.selectedFolder = folder
	msgs, err := s.sess.ListMessages(ctx, folder)
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
	count, totalBytes, err := s.sess.StatMailbox(ctx, folder)
	if err != nil {
		return 0, 0, err
	}
	return int(count), totalBytes, nil
}

func (s *sessionManagerStore) RetrieveFromFolder(ctx context.Context, _ string, folder string, uid uint32) (io.ReadCloser, error) {
	return s.sess.FetchMessage(ctx, folder, uid)
}

func (s *sessionManagerStore) DeleteInFolder(ctx context.Context, _ string, folder string, uid uint32) error {
	return s.sess.DeleteMessage(ctx, folder, uid)
}

// SearchContent implements msgstore.ContentSearcher, evaluating content
// predicates in mail-session so message bodies never cross the proxy.
func (s *sessionManagerStore) SearchContent(ctx context.Context, folder string, uids []uint32, bodyTerms, textTerms []string, needHeaders bool) ([]msgstore.ContentMatch, error) {
	results, err := s.sess.SearchContent(ctx, folder, uids, bodyTerms, textTerms, needHeaders)
	if err != nil {
		return nil, err
	}
	out := make([]msgstore.ContentMatch, 0, len(results))
	for _, r := range results {
		out = append(out, msgstore.ContentMatch{
			UID:         r.GetUid(),
			Headers:     r.GetHeaders(),
			BodyMatches: r.GetBodyMatches(),
			TextMatches: r.GetTextMatches(),
		})
	}
	return out, nil
}

func (s *sessionManagerStore) ExpungeFolder(ctx context.Context, _ string, folder string) error {
	return s.sess.ExpungeMailbox(ctx, folder)
}

func (s *sessionManagerStore) DeliverToFolder(ctx context.Context, _ string, folder string, message io.Reader) error {
	_, err := s.sess.AppendMessage(ctx, folder, message, nil, time.Now())
	return err
}

func (s *sessionManagerStore) RenameFolder(ctx context.Context, _ string, oldName string, newName string) error {
	return s.sess.RenameFolder(ctx, oldName, newName)
}

func (s *sessionManagerStore) AppendToFolder(ctx context.Context, _ string, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	return s.sess.AppendMessage(ctx, folder, r, flags, date)
}

func (s *sessionManagerStore) SetFlagsInFolder(ctx context.Context, _ string, folder string, uid uint32, flags []string) error {
	return s.sess.SetFlags(ctx, folder, uid, flags)
}

func (s *sessionManagerStore) CopyMessage(ctx context.Context, _ string, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	return s.sess.CopyMessage(ctx, srcFolder, uid, destFolder)
}

func (s *sessionManagerStore) UIDValidity(ctx context.Context, _ string, folder string) (uint32, error) {
	return s.sess.UIDValidity(ctx, folder)
}

func (s *sessionManagerStore) UIDNext(ctx context.Context, _ string, folder string) (uint32, error) {
	return s.sess.UIDNext(ctx, folder)
}

// --- mover ---

func (s *sessionManagerStore) MoveMessage(ctx context.Context, _ string, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	return s.sess.MoveMessage(ctx, srcFolder, uid, destFolder)
}

// --- rescanner ---

func (s *sessionManagerStore) Rescan() ([]msgstore.MessageInfo, error) {
	folder := s.selectedFolder
	if folder == "" {
		folder = "INBOX"
	}
	msgs, err := s.sess.RescanFolder(context.Background(), folder)
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
	return s.sess.Logout(context.Background())
}
