package backend_test

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"google.golang.org/grpc"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/notify"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
)

// TestIdle_AbruptDisconnectTearsDownCleanly pins the fix for #202: when a
// client's socket dies mid-IDLE, go-imap's teardown calls Session.Close
// without waiting for the Idle command handler to return, so Close ran
// concurrently with the Idle goroutine (and its keepalive) over the shared
// selected state -- a data race flagged by the race detector. The scenario
// here drops the socket right after a new-mail notification so teardown
// overlaps the notification-handling path; the race detector is the assert.
func TestIdle_AbruptDisconnectTearsDownCleanly(t *testing.T) {
	mr := miniredis.RunT(t)
	sm := newRecoverySM()

	sock := filepath.Join(t.TempDir(), "sm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, sm)
	pb.RegisterMailboxServiceServer(srv, sm)
	pb.RegisterFolderServiceServer(srv, sm)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	cfg := config.Default()
	cfg.Hostname = "teardown.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = nil
	cfg.Redis = config.RedisConfig{URL: "redis://" + mr.Addr()}
	cfg.Timeouts.SessionRecoveryDeadline = "5s"

	stack, err := backend.NewStack(backend.StackConfig{Config: cfg})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	served := make(chan error, 16)
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			go func() { served <- stack.ServeConn(c, config.ModeImap) }()
		}
	}()

	// The window between the read-error return in go-imap's handleIdle and
	// the Idle goroutine noticing is narrow; run the scenario several times
	// so the detector gets real overlap. Each round delivers a fresh UID so
	// the notification always has work to do.
	for round := 0; round < 5; round++ {
		conn, derr := net.DialTimeout("tcp", tcpLn.Addr().String(), 5*time.Second)
		if derr != nil {
			t.Fatalf("round %d dial: %v", round, derr)
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		r := bufio.NewReader(conn)
		if _, rerr := r.ReadString('\n'); rerr != nil { // greeting
			t.Fatalf("round %d greeting: %v", round, rerr)
		}

		send := func(cmd string) {
			t.Helper()
			if _, werr := fmt.Fprintf(conn, "%s\r\n", cmd); werr != nil {
				t.Fatalf("round %d write %q: %v", round, cmd, werr)
			}
		}
		waitFor := func(prefix string) {
			t.Helper()
			for {
				line, rerr := r.ReadString('\n')
				if rerr != nil {
					t.Fatalf("round %d waiting for %q: %v", round, prefix, rerr)
				}
				if strings.HasPrefix(line, prefix) {
					return
				}
			}
		}

		send("a1 LOGIN alice@test.local testpass")
		waitFor("a1 OK")
		send("a2 SELECT INBOX")
		waitFor("a2 OK")
		send("a3 IDLE")
		waitFor("+ ")

		// New mail lands, the notification goes out, and the client's
		// socket dies before the untagged EXISTS can be written.
		sm.addMessage(uint32(10 + round))
		mr.Publish(notify.MailChannel("alice@test.local"), "INBOX")
		_ = conn.Close()

		select {
		case <-served:
			// Handler returned; Session.Close has run against whatever
			// the Idle goroutine was doing.
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: handler did not tear down after abrupt disconnect", round)
		}
	}
}
