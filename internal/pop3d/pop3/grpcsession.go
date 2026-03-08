package pop3

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/infodancer/maildancer/internal/mail-session/client"
	"github.com/infodancer/maildancer/msgstore"
)

// Compile-time assertion that grpcSessionStore satisfies msgstore.MessageStore.
var _ msgstore.MessageStore = (*grpcSessionStore)(nil)

// grpcSessionStore implements msgstore.MessageStore by connecting to a
// mail-session gRPC server via a unix domain socket.
//
// The store is lazy: on the first operation it writes the auth signal to the
// auth pipe (fd 4), reads the socket path from the session pipe (fd 5) — where
// the parent dispatcher wrote it after spawning mail-session — and dials gRPC.
//
// This mirrors the lazy handshake pattern in sessionPipeStore.
type grpcSessionStore struct {
	authPipeW     io.WriteCloser // fd 4: written once, then closed
	sessR         *bufio.Reader  // fd 5: reads socket path from dispatcher
	client        *client.Client // nil until connected
	ready         bool
	handshakeDone bool
}

// NewGrpcSessionStore creates a grpcSessionStore from the auth pipe and the
// session response pipe. The session response pipe will carry the socket path
// written by the parent dispatcher after spawning mail-session in gRPC mode.
func NewGrpcSessionStore(authPipeW io.WriteCloser, sessR io.Reader) msgstore.MessageStore {
	return &grpcSessionStore{
		authPipeW: authPipeW,
		sessR:     bufio.NewReader(sessR),
	}
}

// handshake writes the auth signal, reads the socket path from the dispatcher,
// and dials the gRPC connection.
func (g *grpcSessionStore) handshake(mailbox string) (retErr error) {
	g.handshakeDone = true

	defer func() {
		if err := g.authPipeW.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close auth pipe: %w", err)
		}
	}()

	if err := validateToken("mailbox", mailbox); err != nil {
		return err
	}

	sig := &authSignal{Version: 1, Username: mailbox}
	if err := writeAuthSignal(g.authPipeW, sig); err != nil {
		return fmt.Errorf("write auth signal: %w", err)
	}

	// Read the socket path from fd 5. The parent dispatcher writes it after
	// spawning mail-session and receiving READY.
	line, err := g.sessR.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read socket path from dispatcher: %w", err)
	}
	socketPath := strings.TrimSpace(line)
	if socketPath == "" {
		return fmt.Errorf("empty socket path from dispatcher")
	}

	c, err := client.Dial(socketPath)
	if err != nil {
		return fmt.Errorf("dial mail-session gRPC: %w", err)
	}
	g.client = c
	g.ready = true
	return nil
}

func (g *grpcSessionStore) ensureReady(mailbox string) error {
	if g.ready {
		return nil
	}
	if g.handshakeDone {
		return fmt.Errorf("gRPC session handshake already failed; store is not usable")
	}
	return g.handshake(mailbox)
}

func (g *grpcSessionStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	if err := g.ensureReady(mailbox); err != nil {
		return nil, err
	}
	return g.client.List(ctx, mailbox)
}

func (g *grpcSessionStore) Retrieve(ctx context.Context, mailbox, uid string) (io.ReadCloser, error) {
	if err := g.ensureReady(mailbox); err != nil {
		return nil, err
	}
	return g.client.Retrieve(ctx, mailbox, uid)
}

func (g *grpcSessionStore) Delete(ctx context.Context, mailbox, uid string) error {
	if err := g.ensureReady(mailbox); err != nil {
		return err
	}
	return g.client.Delete(ctx, mailbox, uid)
}

func (g *grpcSessionStore) Expunge(ctx context.Context, mailbox string) error {
	if err := g.ensureReady(mailbox); err != nil {
		return err
	}
	return g.client.Expunge(ctx, mailbox)
}

func (g *grpcSessionStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	if err := g.ensureReady(mailbox); err != nil {
		return 0, 0, err
	}
	return g.client.Stat(ctx, mailbox)
}
