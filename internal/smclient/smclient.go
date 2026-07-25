// Package smclient is the shared session-manager client for the protocol
// daemons (imapd, pop3d). It owns the gRPC dial (unix socket or mTLS), the
// Login/Logout session RPCs, the session-token metadata convention, and the
// proxied mailbox/folder RPC surface, using mail-session proto types
// directly.
//
// Extracted from the daemons' previously copy-pasted clients (issue #179,
// session-recovery-design.md): the transparent session-recovery engine must
// exist exactly once, and this package is where it lives.
package smclient

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

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Config selects the session-manager endpoint. Exactly one of Socket or
// Address must be set; Address requires the mTLS material.
type Config struct {
	// Socket is the unix domain socket path for same-host deployments.
	Socket string
	// Address is the TCP address for network mode (mTLS).
	Address    string
	CACert     string
	ClientCert string
	ClientKey  string
}

// Client wraps a gRPC connection to the session-manager service.
// It handles authentication via Login/Logout and provides proxied mailbox
// and folder operations using mail-session proto types directly.
type Client struct {
	conn    *grpc.ClientConn
	session smpb.SessionServiceClient
	mailbox pb.MailboxServiceClient
	folders pb.FolderServiceClient
	logger  *slog.Logger
}

// New connects to the session-manager and returns a client. The underlying
// gRPC connection is lazy: no network activity happens until the first RPC.
func New(cfg Config, logger *slog.Logger) (*Client, error) {
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

	return &Client{
		conn:    conn,
		session: smpb.NewSessionServiceClient(conn),
		mailbox: pb.NewMailboxServiceClient(conn),
		folders: pb.NewFolderServiceClient(conn),
		logger:  logger,
	}, nil
}

// Login authenticates a user via the session-manager and returns a session token
// and the authenticated mailbox identifier.
func (c *Client) Login(ctx context.Context, username, password, clientIP string) (token, mailbox string, err error) {
	resp, err := c.session.Login(ctx, &smpb.LoginRequest{
		Username: username,
		Password: password,
		ClientIp: clientIP,
	})
	if err != nil {
		return "", "", fmt.Errorf("session-manager login: %w", err)
	}
	return resp.SessionToken, resp.Mailbox, nil
}

// Logout releases a session via the session-manager.
func (c *Client) Logout(ctx context.Context, token string) error {
	_, err := c.session.Logout(ctx, &smpb.LogoutRequest{
		SessionToken: token,
	})
	if err != nil {
		return fmt.Errorf("session-manager logout: %w", err)
	}
	return nil
}

// tokenCtx returns a context with the session token in gRPC metadata.
func tokenCtx(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("session-token", token))
}

// --- MailboxService RPCs ---

// ListMessages returns message metadata for all messages in the given folder.
func (c *Client) ListMessages(ctx context.Context, token, folder string) ([]*pb.MessageInfo, error) {
	resp, err := c.mailbox.List(tokenCtx(ctx, token), &pb.ListRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	return resp.Messages, nil
}

// StatMailbox returns the message count and total byte size for a folder.
func (c *Client) StatMailbox(ctx context.Context, token, folder string) (int32, int64, error) {
	resp, err := c.mailbox.Stat(tokenCtx(ctx, token), &pb.StatRequest{Folder: folder})
	if err != nil {
		return 0, 0, err
	}
	return resp.Count, resp.TotalBytes, nil
}

// FetchMessage retrieves a message by UID. The returned ReadCloser assembles
// the server-streamed chunks into a contiguous byte stream.
func (c *Client) FetchMessage(ctx context.Context, token, folder string, uid uint32) (io.ReadCloser, error) {
	stream, err := c.mailbox.Fetch(tokenCtx(ctx, token), &pb.FetchRequest{
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

// SearchContent evaluates content predicates server-side, returning header
// bytes and per-term match booleans per UID. Message bodies are scanned in
// mail-session and never returned across the proxy. Results are proto types;
// the store adapter converts them to msgstore.ContentMatch.
func (c *Client) SearchContent(ctx context.Context, token, folder string, uids []uint32, bodyTerms, textTerms []string, needHeaders bool) ([]*pb.SearchContentResult, error) {
	resp, err := c.mailbox.SearchContent(tokenCtx(ctx, token), &pb.SearchContentRequest{
		Folder:      folder,
		Uids:        uids,
		BodyTerms:   bodyTerms,
		TextTerms:   textTerms,
		NeedHeaders: needHeaders,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetResults(), nil
}

// SetFlags replaces the complete flag set on a message.
func (c *Client) SetFlags(ctx context.Context, token, folder string, uid uint32, flags []string) error {
	_, err := c.mailbox.SetFlags(tokenCtx(ctx, token), &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  flags,
	})
	return err
}

// DeleteMessage marks a message with \Deleted flag in a folder (IMAP-style
// soft delete via SetFlags).
func (c *Client) DeleteMessage(ctx context.Context, token, folder string, uid uint32) error {
	_, err := c.mailbox.SetFlags(tokenCtx(ctx, token), &pb.SetFlagsRequest{
		Folder: folder,
		Uid:    uid,
		Flags:  []string{"\\Deleted"},
	})
	return err
}

// Delete marks a message for POP3-style deletion via the Delete RPC.
func (c *Client) Delete(ctx context.Context, token string, uid uint32) error {
	_, err := c.mailbox.Delete(tokenCtx(ctx, token), &pb.DeleteRequest{Uid: uid})
	return err
}

// ExpungeMailbox permanently removes all deleted messages in a folder.
func (c *Client) ExpungeMailbox(ctx context.Context, token, folder string) error {
	_, err := c.mailbox.Expunge(tokenCtx(ctx, token), &pb.ExpungeRequest{Folder: folder})
	return err
}

// CopyMessage copies a message between folders.
func (c *Client) CopyMessage(ctx context.Context, token, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	resp, err := c.mailbox.Copy(tokenCtx(ctx, token), &pb.CopyRequest{
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
func (c *Client) MoveMessage(ctx context.Context, token, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	resp, err := c.mailbox.Move(tokenCtx(ctx, token), &pb.MoveRequest{
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
func (c *Client) AppendMessage(ctx context.Context, token, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("read message: %w", err)
	}

	stream, err := c.mailbox.Append(tokenCtx(ctx, token))
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
func (c *Client) UIDValidity(ctx context.Context, token, folder string) (uint32, error) {
	resp, err := c.mailbox.UIDValidity(tokenCtx(ctx, token), &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.UidValidity, nil
}

// UIDNext returns the next UID that will be assigned in a folder.
func (c *Client) UIDNext(ctx context.Context, token, folder string) (uint32, error) {
	resp, err := c.mailbox.UIDValidity(tokenCtx(ctx, token), &pb.UIDValidityRequest{Folder: folder})
	if err != nil {
		return 0, err
	}
	return resp.UidNext, nil
}

// RescanFolder re-reads a folder and returns only new messages since the last List or Rescan.
func (c *Client) RescanFolder(ctx context.Context, token, folder string) ([]*pb.MessageInfo, error) {
	resp, err := c.mailbox.Rescan(tokenCtx(ctx, token), &pb.RescanRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	return resp.NewMessages, nil
}

// --- FolderService RPCs ---

// ListFolders returns all folder names.
func (c *Client) ListFolders(ctx context.Context, token string) ([]string, error) {
	resp, err := c.folders.ListFolders(tokenCtx(ctx, token), &pb.ListFoldersRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Folders, nil
}

// CreateFolder creates a new folder.
func (c *Client) CreateFolder(ctx context.Context, token, name string) error {
	_, err := c.folders.CreateFolder(tokenCtx(ctx, token), &pb.CreateFolderRequest{Name: name})
	return err
}

// DeleteFolder removes a folder.
func (c *Client) DeleteFolder(ctx context.Context, token, name string) error {
	_, err := c.folders.DeleteFolder(tokenCtx(ctx, token), &pb.DeleteFolderRequest{Name: name})
	return err
}

// RenameFolder renames a folder.
func (c *Client) RenameFolder(ctx context.Context, token, oldName, newName string) error {
	_, err := c.folders.RenameFolder(tokenCtx(ctx, token), &pb.RenameFolderRequest{
		OldName: oldName,
		NewName: newName,
	})
	return err
}

// Conn exposes the underlying gRPC connection so other session-manager
// services can be reached over the same link -- the protocol dispatchers use it
// for the accept-time peer gate (#206) rather than opening a second connection
// or duplicating the dial and mTLS setup.
//
// The connection's lifecycle stays with the Client: callers must not close it.
func (c *Client) Conn() grpc.ClientConnInterface {
	return c.conn
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
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
