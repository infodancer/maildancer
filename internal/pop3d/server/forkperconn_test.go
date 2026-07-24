package server_test

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

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/infodancer/maildancer/internal/pop3d/server"
	"github.com/infodancer/maildancer/internal/proctest"
)

// TestServer_ForksProcessPerConnection asserts the process model that
// infodancer/docs/mail-security-model.md requires of pop3d: the listener
// forks a protocol-handler subprocess per accepted connection, so the POP3
// conversation with the remote client never runs in the listener process.
//
// Currently expected to fail: pop3d serves every connection as a goroutine of
// the single listener process (Listener.acceptLoop -> go handleConnection).
// Issue #179 records the decision to re-architect imapd this way and to give
// pop3d the same treatment if it shares the goroutine model -- it does.
func TestServer_ForksProcessPerConnection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Session-manager endpoint: configured but never dialed -- the gRPC
	// client is lazy and this test does not authenticate.
	sock := filepath.Join(t.TempDir(), "sm.sock")
	smClient, err := pop3.NewSessionManagerClient(config.SessionManagerConfig{Socket: sock}, logger)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer smClient.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here

	// Free-port dance; the server does not expose its bound addresses.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModePop3}}

	srv, err := server.New(server.Config{Cfg: &cfg, Logger: logger})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.SetHandler(pop3.Handler(cfg.Hostname, smClient, nil, &metrics.NoopCollector{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	defer srv.Shutdown()

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
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// That process must be a child forked for this connection, not the
	// listener itself.
	kids, err := proctest.WaitForNewChildren(baseline, 1, 2*time.Second)
	if err != nil {
		t.Fatalf("pop3d must fork a protocol-handler process per connection "+
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
