package pop3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// SessionManagerClient wraps a gRPC connection to the session-manager service.
// It handles authentication via Login/Logout and provides proxied mailbox
// operations using mail-session proto types directly.
type SessionManagerClient struct {
	conn    *grpc.ClientConn
	session smpb.SessionServiceClient
	mailbox pb.MailboxServiceClient
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
func tokenCtx(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("session-token", token))
}

// ListMessages returns message metadata for all messages in the given folder.
func (c *SessionManagerClient) ListMessages(ctx context.Context, token, folder string) ([]*pb.MessageInfo, error) {
	resp, err := c.mailbox.List(tokenCtx(ctx, token), &pb.ListRequest{Folder: folder})
	if err != nil {
		return nil, err
	}
	return resp.Messages, nil
}

// StatMailbox returns the message count and total byte size for a folder.
func (c *SessionManagerClient) StatMailbox(ctx context.Context, token, folder string) (int32, int64, error) {
	resp, err := c.mailbox.Stat(tokenCtx(ctx, token), &pb.StatRequest{Folder: folder})
	if err != nil {
		return 0, 0, err
	}
	return resp.Count, resp.TotalBytes, nil
}

// FetchMessage retrieves a message by UID. The returned ReadCloser assembles
// the server-streamed chunks into a contiguous byte stream.
func (c *SessionManagerClient) FetchMessage(ctx context.Context, token, folder, uid string) (io.ReadCloser, error) {
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

// DeleteMessage marks a message for POP3-style deletion.
func (c *SessionManagerClient) DeleteMessage(ctx context.Context, token, uid string) error {
	_, err := c.mailbox.Delete(tokenCtx(ctx, token), &pb.DeleteRequest{Uid: uid})
	return err
}

// ExpungeMailbox permanently removes all deleted messages in a folder.
func (c *SessionManagerClient) ExpungeMailbox(ctx context.Context, token, folder string) error {
	_, err := c.mailbox.Expunge(tokenCtx(ctx, token), &pb.ExpungeRequest{Folder: folder})
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
