// Package client provides a gRPC client for the mail-session service.
// It implements msgstore.MessageStore and msgstore.FolderStore interfaces,
// allowing drop-in replacement for the subprocess-based mail-session transport.
package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/infodancer/maildancer/msgstore"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// Client wraps the generated gRPC stubs for the mail-session service.
// It implements msgstore.MessageStore and msgstore.FolderStore.
type Client struct {
	conn    *grpc.ClientConn
	mailbox pb.MailboxServiceClient
	folders pb.FolderServiceClient
	watch   pb.WatchServiceClient
}

// Dial connects to a mail-session gRPC server over a unix domain socket.
func Dial(socketPath string) (*Client, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", socketPath, err)
	}
	return &Client{
		conn:    conn,
		mailbox: pb.NewMailboxServiceClient(conn),
		folders: pb.NewFolderServiceClient(conn),
		watch:   pb.NewWatchServiceClient(conn),
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// ── msgstore.MessageStore implementation ─────────────────────────────────────

// List returns message metadata for the given mailbox.
// The mailbox parameter is ignored — the server's mailbox was set at startup.
func (c *Client) List(ctx context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return c.ListInFolder(ctx, "", "INBOX")
}

// Retrieve returns the full message content by UID.
func (c *Client) Retrieve(ctx context.Context, _ string, uid string) (io.ReadCloser, error) {
	return c.RetrieveFromFolder(ctx, "", "INBOX", uid)
}

// Delete marks a message for POP3-style deletion.
func (c *Client) Delete(ctx context.Context, _ string, uid string) error {
	_, err := c.mailbox.Delete(ctx, &pb.DeleteRequest{Uid: uid})
	return err
}

// Expunge permanently removes all POP3-marked messages.
func (c *Client) Expunge(ctx context.Context, _ string) error {
	_, err := c.mailbox.Commit(ctx, &pb.CommitRequest{})
	return err
}

// Stat returns the message count and total size.
func (c *Client) Stat(ctx context.Context, _ string) (int, int64, error) {
	resp, err := c.mailbox.Stat(ctx, &pb.StatRequest{Folder: "INBOX"})
	if err != nil {
		return 0, 0, err
	}
	return int(resp.GetCount()), resp.GetTotalBytes(), nil
}

// ── msgstore.FolderStore implementation ──────────────────────────────────────

// CreateFolder creates a new folder.
func (c *Client) CreateFolder(ctx context.Context, _ string, folder string) error {
	_, err := c.folders.CreateFolder(ctx, &pb.CreateFolderRequest{Name: folder})
	return err
}

// ListFolders returns all folder names.
func (c *Client) ListFolders(ctx context.Context, _ string) ([]string, error) {
	resp, err := c.folders.ListFolders(ctx, &pb.ListFoldersRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetFolders(), nil
}

// DeleteFolder removes a folder.
func (c *Client) DeleteFolder(ctx context.Context, _ string, folder string) error {
	_, err := c.folders.DeleteFolder(ctx, &pb.DeleteFolderRequest{Name: folder})
	return err
}

// ListInFolder returns message metadata for all messages in a folder.
func (c *Client) ListInFolder(ctx context.Context, _ string, folder string) ([]msgstore.MessageInfo, error) {
	resp, err := c.mailbox.List(ctx, &pb.ListRequest{Folder: folder})
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

// StatFolder returns message count and total size for a folder.
func (c *Client) StatFolder(ctx context.Context, _ string, folder string) (int, int64, error) {
	resp, err := c.mailbox.Stat(ctx, &pb.StatRequest{Folder: folder})
	if err != nil {
		return 0, 0, err
	}
	return int(resp.GetCount()), resp.GetTotalBytes(), nil
}

// RetrieveFromFolder returns the full message content from a folder.
func (c *Client) RetrieveFromFolder(ctx context.Context, _ string, folder string, uid string) (io.ReadCloser, error) {
	stream, err := c.mailbox.Fetch(ctx, &pb.FetchRequest{Folder: folder, Uid: uid})
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

// DeleteInFolder marks a message in a folder for deletion via IMAP \Deleted flag.
func (c *Client) DeleteInFolder(ctx context.Context, _ string, folder string, uid string) error {
	_, err := c.mailbox.SetFlags(ctx, &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  []string{"\\Deleted"},
	})
	return err
}

// ExpungeFolder removes all \Deleted messages from a folder.
func (c *Client) ExpungeFolder(ctx context.Context, _ string, folder string) error {
	_, err := c.mailbox.Expunge(ctx, &pb.ExpungeRequest{Folder: folder})
	return err
}

// DeliverToFolder delivers a message to a specific folder.
func (c *Client) DeliverToFolder(ctx context.Context, _ string, folder string, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	stream, err := c.mailbox.Append(ctx)
	if err != nil {
		return err
	}

	// Send metadata.
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{
				Folder: folder,
				Date:   time.Now().Format(time.RFC3339),
			},
		},
	}); err != nil {
		return err
	}

	// Send body in 64KB chunks.
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

// RenameFolder renames a folder.
func (c *Client) RenameFolder(ctx context.Context, _ string, oldName string, newName string) error {
	_, err := c.folders.RenameFolder(ctx, &pb.RenameFolderRequest{
		OldName: oldName,
		NewName: newName,
	})
	return err
}

// AppendToFolder stores a message in a folder with explicit flags and date.
func (c *Client) AppendToFolder(ctx context.Context, _ string, folder string, r io.Reader, flags []string, date time.Time) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read message: %w", err)
	}

	stream, err := c.mailbox.Append(ctx)
	if err != nil {
		return "", err
	}

	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{
				Folder: folder,
				Flags:  flags,
				Date:   date.Format(time.RFC3339),
			},
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

// SetFlagsInFolder replaces the complete flag set on a message.
func (c *Client) SetFlagsInFolder(ctx context.Context, _ string, folder string, uid string, flags []string) error {
	_, err := c.mailbox.SetFlags(ctx, &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  flags,
	})
	return err
}

// CopyMessage copies a message between folders.
func (c *Client) CopyMessage(ctx context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	resp, err := c.mailbox.Copy(ctx, &pb.CopyRequest{
		Folder:     srcFolder,
		Uid:        uid,
		DestFolder: destFolder,
	})
	if err != nil {
		return "", err
	}
	return resp.GetNewUid(), nil
}

// UIDValidity returns the UIDVALIDITY for a folder.
func (c *Client) UIDValidity(ctx context.Context, _ string, folder string) (uint32, error) {
	resp, err := c.mailbox.UIDValidity(ctx, &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.GetUidValidity(), nil
}

// MoveMessage atomically moves a message between folders.
// The mailbox parameter is ignored — the server's mailbox was set at startup.
func (c *Client) MoveMessage(ctx context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	resp, err := c.mailbox.Move(ctx, &pb.MoveRequest{
		Uid:        uid,
		SrcFolder:  srcFolder,
		DestFolder: destFolder,
	})
	if err != nil {
		return "", err
	}
	return resp.GetNewUid(), nil
}

// Rescan re-reads a folder and returns only messages that appeared since the
// last List or Rescan call. Used by IMAP IDLE to detect new mail.
func (c *Client) Rescan(ctx context.Context, folder string) ([]msgstore.MessageInfo, error) {
	resp, err := c.mailbox.Rescan(ctx, &pb.RescanRequest{Folder: folder})
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
	_ msgstore.MessageStore = (*Client)(nil)
	_ msgstore.FolderStore  = (*Client)(nil)
)
