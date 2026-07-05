package server

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
)

// lockedBuffer is a concurrency-safe io.Writer for capturing log output, since
// records may arrive from both handleConnection and the idle-monitor goroutine.
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

// TestHandleConnection_RecoversHandlerPanic verifies that a panic in the
// connection handler is recovered rather than escaping the per-connection
// goroutine (which would crash the whole pop3d process and drop every other
// connection). Regression test for issue #137.
func TestHandleConnection_RecoversHandlerPanic(t *testing.T) {
	logBuf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	l := NewListener(ListenerConfig{
		Address:     "test",
		Mode:        config.ModePop3,
		IdleTimeout: time.Minute,
		Logger:      logger,
		Handler: func(_ context.Context, _ *Connection) {
			panic("boom in handler")
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	// Drain anything the server writes so no goroutine blocks on the sync pipe.
	go io.Copy(io.Discard, clientConn) //nolint:errcheck

	// handleConnection calls wg.Done(); balance it so the deferred decrement is valid.
	l.wg.Add(1)
	done := make(chan struct{})
	go func() {
		// If the panic were not recovered inside handleConnection, it would
		// propagate here and crash the test binary -- which is exactly the
		// daemon-crash behavior this test guards against.
		l.handleConnection(context.Background(), serverConn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return; handler panic was not recovered")
	}

	out := logBuf.String()
	if !strings.Contains(out, "panic serving connection") {
		t.Errorf("expected recovered panic to be logged, got: %q", out)
	}
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("expected error-level log, got: %q", out)
	}
	if !strings.Contains(out, "boom in handler") {
		t.Errorf("expected the panic value in the log, got: %q", out)
	}
	if !strings.Contains(out, "stack=") {
		t.Errorf("expected a stack trace in the log, got: %q", out)
	}
}

// TestHandleConnection_SurvivesToServeAgain confirms the goroutine containment
// property: after one connection's handler panics, the listener state is intact
// and a subsequent connection is served normally.
func TestHandleConnection_SurvivesToServeAgain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var served int
	var mu sync.Mutex
	l := NewListener(ListenerConfig{
		Address:     "test",
		Mode:        config.ModePop3,
		IdleTimeout: time.Minute,
		Logger:      logger,
		Handler: func(_ context.Context, _ *Connection) {
			mu.Lock()
			n := served
			served++
			mu.Unlock()
			if n == 0 {
				panic("boom on first connection")
			}
			// second connection returns cleanly
		},
	})

	for i := 0; i < 2; i++ {
		clientConn, serverConn := net.Pipe()
		go io.Copy(io.Discard, clientConn) //nolint:errcheck

		l.wg.Add(1)
		done := make(chan struct{})
		go func() {
			l.handleConnection(context.Background(), serverConn)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d did not complete", i)
		}
		_ = clientConn.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if served != 2 {
		t.Errorf("expected both connections to reach the handler, got served=%d", served)
	}
}
