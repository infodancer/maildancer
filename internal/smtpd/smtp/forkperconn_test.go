package smtp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/proctest"
	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// TestSubprocessServer_ForksHandlerPerConnection asserts the process model
// that infodancer/docs/mail-security-model.md requires of smtpd end to end:
// each accepted connection is handed to its own protocol-handler subprocess.
// Two concurrent client connections must therefore be served by two distinct
// live child processes of the listener.
//
// The child is a stand-in (testdata/connholder) rather than the real
// protocol-handler, for the same reason as TestSubprocessMetricsEndToEnd: a
// real SMTP session needs a running session-manager. The accept loop, the
// fork/exec, and the fd 3 handoff are all the real code paths.
//
// This test also validates the /proc-based detection that the imapd and pop3d
// counterparts rely on: if child observation were broken, this test would fail
// too, so their failures cannot be an artifact of the helper.
func TestSubprocessServer_ForksHandlerPerConnection(t *testing.T) {
	helper := buildConnHolder(t)

	// Free-port dance; SubprocessServer does not expose its bound addresses.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Default()
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModeSmtp}}

	srv := NewSubprocessServer(cfg, helper, "unused-config-path", nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	baseline, err := proctest.Children()
	if err != nil {
		t.Fatalf("snapshot children: %v", err)
	}

	conn1 := dialConnRetry(t, addr)
	defer conn1.Close()
	conn2 := dialConnRetry(t, addr)
	defer conn2.Close()

	kids, err := proctest.WaitForNewChildren(baseline, 2, 5*time.Second)
	if err != nil {
		t.Fatalf("smtpd must fork a protocol-handler process per connection "+
			"(mail-security-model.md): %v", err)
	}
	t.Logf("connections handled by child processes %v", kids)
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

func dialConnRetry(t *testing.T, addr string) net.Conn {
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
