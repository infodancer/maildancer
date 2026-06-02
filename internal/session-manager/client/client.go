// Package client provides a gRPC client for the session-manager service.
//
// Protocol handlers (pop3d, imapd, smtpd) use this package to authenticate
// users and access mailboxes through the session-manager rather than spawning
// mail-session processes directly.
//
// Usage:
//
//	c, err := client.Dial("/run/session-manager/session-manager.sock")
//	token, mailbox, err := c.Login(ctx, "user@example.com", "secret")
//	store := c.NewMessageStore(token)
//	// ... use store for mailbox operations ...
//	_ = c.Logout(ctx, token)
//	_ = c.Close()
package client

import (
	"fmt"

	"context"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client holds a connection to the session-manager gRPC server.
type Client struct {
	conn    *grpc.ClientConn
	session smpb.SessionServiceClient
	mailbox pb.MailboxServiceClient
	folders pb.FolderServiceClient
}

// Dial connects to the session-manager over a unix domain socket.
func Dial(socketPath string) (*Client, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial session-manager %q: %w", socketPath, err)
	}
	return &Client{
		conn:    conn,
		session: smpb.NewSessionServiceClient(conn),
		mailbox: pb.NewMailboxServiceClient(conn),
		folders: pb.NewFolderServiceClient(conn),
	}, nil
}

// Login authenticates a user and creates a mail session.
// Returns the opaque session token and the authenticated mailbox identifier.
// The token must be passed to NewMessageStore and to Logout.
func (c *Client) Login(ctx context.Context, username, password string) (token, mailbox string, err error) {
	resp, err := c.session.Login(ctx, &smpb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", "", fmt.Errorf("session-manager login: %w", err)
	}
	return resp.GetSessionToken(), resp.GetMailbox(), nil
}

// Logout releases a session. When the last reference to a session is released,
// an idle timer starts; if no new Login arrives before it fires, the
// mail-session process is terminated.
func (c *Client) Logout(ctx context.Context, token string) error {
	_, err := c.session.Logout(ctx, &smpb.LogoutRequest{SessionToken: token})
	return err
}

// NewMessageStore returns a msgstore.MessageStore backed by the session-manager.
// All operations are routed to the per-user mail-session associated with token.
// The returned store is safe to use concurrently.
func (c *Client) NewMessageStore(token string) *MessageStore {
	return &MessageStore{
		token:   token,
		mailbox: c.mailbox,
		folders: c.folders,
	}
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
