package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/config"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// SessionManagerClient wraps a gRPC connection to the session-manager service.
// It handles authentication via Login/Logout and provides proxied mailbox
// and folder operations using mail-session proto types directly.
type SessionManagerClient struct {
	conn    *grpc.ClientConn
	session smpb.SessionServiceClient
	mailbox pb.MailboxServiceClient
	folders pb.FolderServiceClient
	logger  *slog.Logger
}

// NewSessionManagerClient connects to the session-manager and returns a client.
// Exactly one of cfg.Socket or cfg.Address must be set.
func NewSessionManagerClient(cfg config.SessionManagerConfig, logger *slog.Logger) (*SessionManagerClient, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var target string
	var opts []grpc.DialOption

	switch {
	case cfg.Socket != "":
		target = "unix:" + cfg.Socket
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	case cfg.Address != "":
		target = cfg.Address
		tlsCfg, err := buildClientTLS(cfg.CACert, cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("session-manager mTLS: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	default:
		return nil, fmt.Errorf("session-manager requires socket or address")
	}

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial session-manager: %w", err)
	}

	return &SessionManagerClient{
		conn:    conn,
		session: smpb.NewSessionServiceClient(conn),
		mailbox: pb.NewMailboxServiceClient(conn),
		folders: pb.NewFolderServiceClient(conn),
		logger:  logger,
	}, nil
}

// Login authenticates a user via the session-manager and returns a session token
// and the authenticated mailbox identifier.
func (c *SessionManagerClient) Login(ctx context.Context, username, password string) (token, mailbox string, err error) {
	resp, err := c.session.Login(ctx, &smpb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", "", fmt.Errorf("session-manager login: %w", err)
	}
	return resp.SessionToken, resp.Mailbox, nil
}

// Logout releases a session via the session-manager.
func (c *SessionManagerClient) Logout(ctx context.Context, token string) error {
	_, err := c.session.Logout(ctx, &smpb.LogoutRequest{
		SessionToken: token,
	})
	if err != nil {
		return fmt.Errorf("session-manager logout: %w", err)
	}
	return nil
}

// tokenCtx returns a context with the session token in gRPC metadata.
func smTokenCtx(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("session-token", token))
}

// --- MailboxService RPCs ---

// ListMessages returns message metadata for all messages in the given folder.
func (c *SessionManagerClient) ListMessages(ctx context.Context, token, folder string) ([]*pb.MessageInfo, error) {
	resp, err := c.mailbox.List(smTokenCtx(ctx, token), &pb.ListRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	return resp.Messages, nil
}

// StatMailbox returns the message count and total byte size for a folder.
func (c *SessionManagerClient) StatMailbox(ctx context.Context, token, folder string) (int32, int64, error) {
	resp, err := c.mailbox.Stat(smTokenCtx(ctx, token), &pb.StatRequest{Folder: folder})
	if err != nil {
		return 0, 0, err
	}
	return resp.Count, resp.TotalBytes, nil
}

// FetchMessage retrieves a message by UID via server-streaming.
func (c *SessionManagerClient) FetchMessage(ctx context.Context, token, folder string, uid uint32) (io.ReadCloser, error) {
	stream, err := c.mailbox.Fetch(smTokenCtx(ctx, token), &pb.FetchRequest{
		Folder: folder,
		Uid:    uid,
	})
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
			return nil, fmt.Errorf("fetch stream: %w", err)
		}
		buf.Write(chunk.Data)
	}
	return io.NopCloser(&buf), nil
}

// SetFlags replaces the complete flag set on a message.
func (c *SessionManagerClient) SetFlags(ctx context.Context, token, folder string, uid uint32, flags []string) error {
	_, err := c.mailbox.SetFlags(smTokenCtx(ctx, token), &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  flags,
	})
	return err
}

// DeleteMessage marks a message with \Deleted flag in a folder.
func (c *SessionManagerClient) DeleteMessage(ctx context.Context, token, folder string, uid uint32) error {
	_, err := c.mailbox.SetFlags(smTokenCtx(ctx, token), &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  []string{"\\Deleted"},
	})
	return err
}

// ExpungeMailbox permanently removes all \Deleted messages in a folder.
func (c *SessionManagerClient) ExpungeMailbox(ctx context.Context, token, folder string) error {
	_, err := c.mailbox.Expunge(smTokenCtx(ctx, token), &pb.ExpungeRequest{Folder: folder})
	return err
}

// CopyMessage copies a message between folders.
func (c *SessionManagerClient) CopyMessage(ctx context.Context, token, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	resp, err := c.mailbox.Copy(smTokenCtx(ctx, token), &pb.CopyRequest{
		Folder:     srcFolder,
		Uid:        uid,
		DestFolder: destFolder,
	})
	if err != nil {
		return 0, err
	}
	return resp.NewUid, nil
}

// MoveMessage atomically moves a message between folders.
func (c *SessionManagerClient) MoveMessage(ctx context.Context, token, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	resp, err := c.mailbox.Move(smTokenCtx(ctx, token), &pb.MoveRequest{
		Uid:        uid,
		SrcFolder:  srcFolder,
		DestFolder: destFolder,
	})
	if err != nil {
		return 0, err
	}
	return resp.NewUid, nil
}

// AppendMessage stores a message in a folder with explicit flags and date via client-streaming.
func (c *SessionManagerClient) AppendMessage(ctx context.Context, token, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("read message: %w", err)
	}

	stream, err := c.mailbox.Append(smTokenCtx(ctx, token))
	if err != nil {
		return 0, err
	}

	// Send metadata.
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{
				Folder: folder,
				Flags:  flags,
				Date:   date.Format(time.RFC3339),
			},
		},
	}); err != nil {
		return 0, err
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
			return 0, err
		}
		off = end
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, err
	}
	return resp.GetUid(), nil
}

// UIDValidity returns the UIDVALIDITY for a folder.
func (c *SessionManagerClient) UIDValidity(ctx context.Context, token, folder string) (uint32, error) {
	resp, err := c.mailbox.UIDValidity(smTokenCtx(ctx, token), &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.UidValidity, nil
}

// UIDNext returns the next UID that will be assigned in a folder.
func (c *SessionManagerClient) UIDNext(ctx context.Context, token, folder string) (uint32, error) {
	resp, err := c.mailbox.UIDValidity(smTokenCtx(ctx, token), &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.UidNext, nil
}

// RescanFolder re-reads a folder and returns only new messages since the last List or Rescan.
func (c *SessionManagerClient) RescanFolder(ctx context.Context, token, folder string) ([]*pb.MessageInfo, error) {
	resp, err := c.mailbox.Rescan(smTokenCtx(ctx, token), &pb.RescanRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	return resp.NewMessages, nil
}

// --- FolderService RPCs ---

// ListFolders returns all folder names.
func (c *SessionManagerClient) ListFolders(ctx context.Context, token string) ([]string, error) {
	resp, err := c.folders.ListFolders(smTokenCtx(ctx, token), &pb.ListFoldersRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Folders, nil
}

// CreateFolder creates a new folder.
func (c *SessionManagerClient) CreateFolder(ctx context.Context, token, name string) error {
	_, err := c.folders.CreateFolder(smTokenCtx(ctx, token), &pb.CreateFolderRequest{Name: name})
	return err
}

// DeleteFolder removes a folder.
func (c *SessionManagerClient) DeleteFolder(ctx context.Context, token, name string) error {
	_, err := c.folders.DeleteFolder(smTokenCtx(ctx, token), &pb.DeleteFolderRequest{Name: name})
	return err
}

// RenameFolder renames a folder.
func (c *SessionManagerClient) RenameFolder(ctx context.Context, token, oldName, newName string) error {
	_, err := c.folders.RenameFolder(smTokenCtx(ctx, token), &pb.RenameFolderRequest{
		OldName: oldName,
		NewName: newName,
	})
	return err
}

// Close closes the underlying gRPC connection.
func (c *SessionManagerClient) Close() error {
	return c.conn.Close()
}

// buildClientTLS creates a TLS config for mTLS connections.
func buildClientTLS(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("invalid CA certificate")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
