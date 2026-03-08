package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/msgstore"
	"google.golang.org/grpc/metadata"
)

// MessageStore implements msgstore.MessageStore and msgstore.FolderStore by
// proxying gRPC calls through the session-manager. Each call attaches the
// session token as gRPC metadata so the server can route to the correct
// per-user mail-session.
type MessageStore struct {
	token   string
	mailbox pb.MailboxServiceClient
	folders pb.FolderServiceClient
}

// tokenCtx injects the session token into the outgoing gRPC metadata.
func (s *MessageStore) tokenCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "session-token", s.token)
}

// ── msgstore.MessageStore ─────────────────────────────────────────────────────

// List returns message metadata for INBOX.
func (s *MessageStore) List(ctx context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return s.ListInFolder(ctx, "", "INBOX")
}

// Stat returns message count and total size for INBOX.
func (s *MessageStore) Stat(ctx context.Context, _ string) (int, int64, error) {
	return s.StatFolder(ctx, "", "INBOX")
}

// Retrieve returns the full message content from INBOX by UID.
func (s *MessageStore) Retrieve(ctx context.Context, _ string, uid string) (io.ReadCloser, error) {
	return s.RetrieveFromFolder(ctx, "", "INBOX", uid)
}

// Delete marks a message in INBOX for POP3-style deletion.
func (s *MessageStore) Delete(ctx context.Context, _ string, uid string) error {
	_, err := s.mailbox.Delete(s.tokenCtx(ctx), &pb.DeleteRequest{Uid: uid})
	return err
}

// Expunge commits all POP3 deletions in INBOX.
func (s *MessageStore) Expunge(ctx context.Context, _ string) error {
	_, err := s.mailbox.Commit(s.tokenCtx(ctx), &pb.CommitRequest{})
	return err
}

// ── msgstore.FolderStore ──────────────────────────────────────────────────────

// ListFolders returns all folder names.
func (s *MessageStore) ListFolders(ctx context.Context, _ string) ([]string, error) {
	resp, err := s.folders.ListFolders(s.tokenCtx(ctx), &pb.ListFoldersRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetFolders(), nil
}

// CreateFolder creates a new folder.
func (s *MessageStore) CreateFolder(ctx context.Context, _ string, folder string) error {
	_, err := s.folders.CreateFolder(s.tokenCtx(ctx), &pb.CreateFolderRequest{Name: folder})
	return err
}

// DeleteFolder removes a folder.
func (s *MessageStore) DeleteFolder(ctx context.Context, _ string, folder string) error {
	_, err := s.folders.DeleteFolder(s.tokenCtx(ctx), &pb.DeleteFolderRequest{Name: folder})
	return err
}

// RenameFolder renames a folder.
func (s *MessageStore) RenameFolder(ctx context.Context, _ string, oldName, newName string) error {
	_, err := s.folders.RenameFolder(s.tokenCtx(ctx), &pb.RenameFolderRequest{OldName: oldName, NewName: newName})
	return err
}

// ListInFolder returns message metadata for the given folder.
func (s *MessageStore) ListInFolder(ctx context.Context, _ string, folder string) ([]msgstore.MessageInfo, error) {
	resp, err := s.mailbox.List(s.tokenCtx(ctx), &pb.ListRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	msgs := make([]msgstore.MessageInfo, 0, len(resp.GetMessages()))
	for _, m := range resp.GetMessages() {
		msgs = append(msgs, msgstore.MessageInfo{
			UID:   m.GetUid(),
			Size:  m.GetSize(),
			Flags: m.GetFlags(),
		})
	}
	return msgs, nil
}

// StatFolder returns message count and total size for the given folder.
func (s *MessageStore) StatFolder(ctx context.Context, _ string, folder string) (int, int64, error) {
	resp, err := s.mailbox.Stat(s.tokenCtx(ctx), &pb.StatRequest{Folder: folder})
	if err != nil {
		return 0, 0, err
	}
	return int(resp.GetCount()), resp.GetTotalBytes(), nil
}

// RetrieveFromFolder returns the full message content from the given folder.
func (s *MessageStore) RetrieveFromFolder(ctx context.Context, _ string, folder, uid string) (io.ReadCloser, error) {
	stream, err := s.mailbox.Fetch(s.tokenCtx(ctx), &pb.FetchRequest{Folder: folder, Uid: uid})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		buf.Write(chunk.GetData())
	}
	return io.NopCloser(&buf), nil
}

// DeleteInFolder marks a message in a folder for IMAP-style deletion.
func (s *MessageStore) DeleteInFolder(ctx context.Context, _ string, folder, uid string) error {
	_, err := s.mailbox.SetFlags(s.tokenCtx(ctx), &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  []string{`\Deleted`},
	})
	return err
}

// ExpungeFolder removes all \Deleted messages from a folder.
func (s *MessageStore) ExpungeFolder(ctx context.Context, _ string, folder string) error {
	_, err := s.mailbox.Expunge(s.tokenCtx(ctx), &pb.ExpungeRequest{Folder: folder})
	return err
}

// DeliverToFolder delivers a message to a folder.
func (s *MessageStore) DeliverToFolder(ctx context.Context, _ string, folder string, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	stream, err := s.mailbox.Append(s.tokenCtx(ctx))
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{Folder: folder, Date: time.Now().Format(time.RFC3339)},
		},
	}); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		end := off + 64*1024
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&pb.AppendRequest{
			Payload: &pb.AppendRequest_Data{Data: data[off:end]},
		}); err != nil {
			return err
		}
		off = end
	}
	_, err = stream.CloseAndRecv()
	return err
}

// AppendToFolder stores a message with explicit flags and date.
func (s *MessageStore) AppendToFolder(ctx context.Context, _ string, folder string, r io.Reader, flags []string, date time.Time) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read message: %w", err)
	}
	stream, err := s.mailbox.Append(s.tokenCtx(ctx))
	if err != nil {
		return "", err
	}
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{Folder: folder, Flags: flags, Date: date.Format(time.RFC3339)},
		},
	}); err != nil {
		return "", err
	}
	for off := 0; off < len(data); {
		end := off + 64*1024
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&pb.AppendRequest{
			Payload: &pb.AppendRequest_Data{Data: data[off:end]},
		}); err != nil {
			return "", err
		}
		off = end
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return "", err
	}
	return resp.GetUid(), nil
}

// SetFlagsInFolder replaces the flag set on a message.
func (s *MessageStore) SetFlagsInFolder(ctx context.Context, _ string, folder, uid string, flags []string) error {
	_, err := s.mailbox.SetFlags(s.tokenCtx(ctx), &pb.SetFlagsRequest{Folder: folder, Uid: uid, Flags: flags})
	return err
}

// CopyMessage copies a message between folders, returning the new UID.
func (s *MessageStore) CopyMessage(ctx context.Context, _ string, srcFolder, uid, destFolder string) (string, error) {
	resp, err := s.mailbox.Copy(s.tokenCtx(ctx), &pb.CopyRequest{Folder: srcFolder, Uid: uid, DestFolder: destFolder})
	if err != nil {
		return "", err
	}
	return resp.GetNewUid(), nil
}

// MoveMessage atomically moves a message between folders, returning the new UID.
func (s *MessageStore) MoveMessage(ctx context.Context, _ string, srcFolder, uid, destFolder string) (string, error) {
	resp, err := s.mailbox.Move(s.tokenCtx(ctx), &pb.MoveRequest{SrcFolder: srcFolder, Uid: uid, DestFolder: destFolder})
	if err != nil {
		return "", err
	}
	return resp.GetNewUid(), nil
}

// UIDValidity returns the UIDVALIDITY for a folder.
func (s *MessageStore) UIDValidity(ctx context.Context, _ string, folder string) (uint32, error) {
	resp, err := s.mailbox.UIDValidity(s.tokenCtx(ctx), &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.GetUidValidity(), nil
}

// Rescan re-reads a folder and returns messages that appeared since the last call.
func (s *MessageStore) Rescan(ctx context.Context, folder string) ([]msgstore.MessageInfo, error) {
	resp, err := s.mailbox.Rescan(s.tokenCtx(ctx), &pb.RescanRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	msgs := make([]msgstore.MessageInfo, 0, len(resp.GetNewMessages()))
	for _, m := range resp.GetNewMessages() {
		msgs = append(msgs, msgstore.MessageInfo{
			UID:   m.GetUid(),
			Size:  m.GetSize(),
			Flags: m.GetFlags(),
		})
	}
	return msgs, nil
}

// Compile-time interface checks.
var (
	_ msgstore.MessageStore = (*MessageStore)(nil)
	_ msgstore.FolderStore  = (*MessageStore)(nil)
)
