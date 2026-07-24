package backend_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/proctest"
)

// TestDispatcher_ForksProcessPerConnection is the acceptance gate for the
// process model that infodancer/docs/mail-security-model.md requires of
// imapd (issue #179): the listener forks a protocol-handler subprocess per
// accepted connection, so the IMAP conversation with the remote client never
// runs in the listener process.
//
// It drives the real production path: the dispatcher spawns the actual imapd
// binary (built from cmd/imapd), the child recovers the connection from
// fd 3, re-reads the config file, and emits the go-imap greeting.
func TestDispatcher_ForksProcessPerConnection(t *testing.T) {
	bin := buildImapd(t)

	// Child-side config: the handler re-reads this file. The
	// session-manager socket is never dialed (the gRPC client is lazy and
	// this test does not authenticate); no Redis means a nil subscriber,
	// which is supported.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "imapd.toml")
	sock := filepath.Join(dir, "sm.sock")
	toml := fmt.Sprintf("[session-manager]\nsocket = %q\n", sock)
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

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

	dispatcher, err := backend.NewDispatcher(backend.DispatcherConfig{
		Config:     cfg,
		ExecPath:   bin,
		ConfigPath: cfgPath,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dispatcher.Run(ctx) }()

	baseline, err := proctest.Children()
	if err != nil {
		t.Fatalf("snapshot children: %v", err)
	}

	conn := dialRetry(t, addr)
	defer conn.Close()

	// The greeting proves a live session: it is produced by the child's
	// go-imap server after fd-3 recovery, not by the dispatcher.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	kids, err := proctest.WaitForNewChildren(baseline, 1, 5*time.Second)
	if err != nil {
		t.Fatalf("imapd must fork a protocol-handler process per connection "+
			"(mail-security-model.md, issue #179): %v", err)
	}
	t.Logf("connection handled by child process(es) %v", kids)

	// A second concurrent connection gets its own child.
	conn2 := dialRetry(t, addr)
	defer conn2.Close()
	if _, err := proctest.WaitForNewChildren(baseline, 2, 5*time.Second); err != nil {
		t.Fatalf("second connection did not get its own handler process: %v", err)
	}
}

// buildImapd compiles the real imapd binary and returns its path.
func buildImapd(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "imapd")
	cmd := exec.Command("go", "build", "-o", out, "github.com/infodancer/maildancer/cmd/imapd")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build imapd: %v", err)
	}
	return out
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
