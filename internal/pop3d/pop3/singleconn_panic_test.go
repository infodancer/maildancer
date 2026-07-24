package pop3

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

// lockedBuffer is a concurrency-safe io.Writer for capturing log output, since
// records may arrive from both the session and the idle-monitor goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// panicStack builds a Stack around a handler that panics, bypassing NewStack
// (which requires a session-manager and installs the real POP3 handler).
func panicStack(t *testing.T, logger *slog.Logger, handler server.ConnectionHandler) *Stack {
	t.Helper()
	cfg := config.Default()
	cfg.Hostname = "panic.local"
	srv, err := server.New(server.Config{Cfg: &cfg, Logger: logger})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.SetHandler(handler)
	return &Stack{server: srv, logger: logger}
}

// TestRunSingleConn_RecoversHandlerPanic verifies that a panic in the session
// handler is recovered, logged with its stack, and surfaced as an error
// rather than crashing the handler process without a structured log.
// Continuation of the issue #137 guarantee on the fork-per-connection path
// (#179).
func TestRunSingleConn_RecoversHandlerPanic(t *testing.T) {
	logBuf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	stack := panicStack(t, logger, func(_ context.Context, _ *server.Connection) {
		panic("boom in handler")
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go io.Copy(io.Discard, clientConn) //nolint:errcheck // draining a pipe that gets closed at test teardown; the resulting error is expected and not checked

	errCh := make(chan error, 1)
	go func() { errCh <- stack.RunSingleConn(serverConn, config.ModePop3) }()

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "panic") {
			t.Errorf("expected a panic error from RunSingleConn, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunSingleConn did not return; handler panic was not recovered")
	}

	out := logBuf.String()
	if !strings.Contains(out, "panic serving connection") {
		t.Errorf("expected recovered panic to be logged, got: %q", out)
	}
	if !strings.Contains(out, "boom in handler") {
		t.Errorf("expected the panic value in the log, got: %q", out)
	}
	if !strings.Contains(out, "stack=") {
		t.Errorf("expected a stack trace in the log, got: %q", out)
	}
}

// TestRunSingleConn_IdleTimeoutClosesConnection verifies that an idle session
// is torn down by the idle monitor. On the fork-per-connection path this is
// what keeps an idle client from pinning a handler process (and its
// dispatcher connection slot) indefinitely.
func TestRunSingleConn_IdleTimeoutClosesConnection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A handler that blocks reading until the connection is closed under it.
	stack := panicStack(t, logger, func(_ context.Context, c *server.Connection) {
		_, _ = c.Reader().ReadString('\n')
	})
	cfg := stack.server.Config()
	cfg.Timeouts.Connection = "50ms"

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		_ = stack.RunSingleConn(serverConn, config.ModePop3)
		close(done)
	}()

	select {
	case <-done:
		// good: the idle monitor closed the connection and the session ended
	case <-time.After(5 * time.Second):
		t.Fatal("idle session was not torn down by the idle monitor")
	}
}
