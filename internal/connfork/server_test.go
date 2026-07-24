package connfork

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/proctest"
)

// TestServer_SpawnsHandlerPerConnection asserts the core contract: each
// accepted connection is handed to its own live child process, with
// OnConnStart/OnConnEnd paired around the child's lifetime.
func TestServer_SpawnsHandlerPerConnection(t *testing.T) {
	helper := buildConnHolder(t)
	addr := freePort(t)

	var starts, ends atomic.Int32
	srv := NewServer(Config{
		Listeners:   []Listener{{Address: addr, Mode: "test"}},
		ExecPath:    helper,
		OnConnStart: func() { starts.Add(1) },
		OnConnEnd:   func() { ends.Add(1) },
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	baseline, err := proctest.Children()
	if err != nil {
		t.Fatalf("snapshot children: %v", err)
	}

	conn1 := dialRetry(t, addr)
	conn2 := dialRetry(t, addr)

	kids, err := proctest.WaitForNewChildren(baseline, 2, 5*time.Second)
	if err != nil {
		t.Fatalf("want one child process per connection: %v", err)
	}
	t.Logf("connections handled by child processes %v", kids)

	waitCount(t, &starts, 2, "OnConnStart")
	if got := ends.Load(); got != 0 {
		t.Fatalf("OnConnEnd fired before any connection closed: %d", got)
	}

	_ = conn1.Close()
	_ = conn2.Close()
	waitCount(t, &ends, 2, "OnConnEnd")
}

// TestServer_MaxConnsLimitsLiveHandlers asserts the limiter: with MaxConns=1
// a second connection is not handed to a handler until the first handler is
// reaped.
func TestServer_MaxConnsLimitsLiveHandlers(t *testing.T) {
	helper := buildConnHolder(t)
	addr := freePort(t)

	var starts, ends atomic.Int32
	srv := NewServer(Config{
		Listeners:   []Listener{{Address: addr, Mode: "test"}},
		ExecPath:    helper,
		OnConnStart: func() { starts.Add(1) },
		OnConnEnd:   func() { ends.Add(1) },
		MaxConns:    1,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	conn1 := dialRetry(t, addr)
	waitCount(t, &starts, 1, "OnConnStart")

	// Second connection sits in the kernel backlog; no second handler may
	// start while the first is live.
	conn2 := dialRetry(t, addr)
	defer conn2.Close()
	time.Sleep(250 * time.Millisecond)
	if got := starts.Load(); got != 1 {
		t.Fatalf("second handler started despite MaxConns=1: starts=%d", got)
	}

	// Releasing the first connection lets its handler exit and be reaped,
	// freeing the slot for the queued connection.
	_ = conn1.Close()
	waitCount(t, &starts, 2, "OnConnStart after slot freed")
	waitCount(t, &ends, 1, "OnConnEnd")
}

// buildConnHolder compiles the stand-in handler and returns its path.
func buildConnHolder(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "connholder")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/connholder")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build connholder helper: %v", err)
	}
	return out
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func dialRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitCount(t *testing.T, c *atomic.Int32, want int32, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			if got := c.Load(); got != want {
				t.Fatalf("%s: want exactly %d, got %d", what, want, got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: want %d, still %d after timeout", what, want, c.Load())
}
