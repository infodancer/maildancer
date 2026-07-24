package backend_test

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/proctest"
)

// TestStack_ForksProcessPerConnection asserts the process model that
// infodancer/docs/mail-security-model.md requires of imapd: the listener
// forks a protocol-handler subprocess per accepted connection, so the IMAP
// conversation with the remote client never runs in the listener process.
//
// Currently expected to fail: imapd serves every connection as a goroutine of
// the single listener process (go-imap/v2 Serve). Issue #179 records the
// decision to re-architect to fork-per-connection, matching smtpd.
func TestStack_ForksProcessPerConnection(t *testing.T) {
	// Session-manager endpoint: configured but never dialed -- the gRPC
	// client is lazy and this test does not authenticate.
	sock := filepath.Join(t.TempDir(), "sm.sock")

	// Free-port dance; Stack does not expose its bound addresses.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModeImap}}

	stack, err := backend.NewStack(backend.StackConfig{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	defer stack.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = stack.Run(ctx) }()

	baseline, err := proctest.Children()
	if err != nil {
		t.Fatalf("snapshot children: %v", err)
	}

	conn := dialRetry(t, addr)
	defer conn.Close()

	// The greeting proves a live session is underway with some process.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// That process must be a child forked for this connection, not the
	// listener itself.
	kids, err := proctest.WaitForNewChildren(baseline, 1, 2*time.Second)
	if err != nil {
		t.Fatalf("imapd must fork a protocol-handler process per connection "+
			"(mail-security-model.md, issue #179); the session is being served in-process: %v", err)
	}
	t.Logf("connection handled by child process(es) %v", kids)
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
