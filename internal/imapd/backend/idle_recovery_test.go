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

// TestIdle_MailDeliveredAcrossRestartIsPushed pins the outage catch-up
// promise of the session-recovery design (#179, #201): a message delivered
// while the session-manager was restarting must reach an IDLE client as an
// untagged EXISTS after transparent recovery. The upstream mail-session's
// incremental Rescan cannot provide this -- the fresh process's baseline
// absorbs outage-window mail -- so the idle path must diff the folder
// listing against the connection's own message list.
func TestIdle_MailDeliveredAcrossRestartIsPushed(t *testing.T) {
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
	cfg.Hostname = "recovery.local"
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
	go func() {
		c, aerr := tcpLn.Accept()
		if aerr != nil {
			return
		}
		_ = stack.ServeConn(c, config.ModeImap)
	}()

	conn, err := net.DialTimeout("tcp", tcpLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting: %v", err)
	}

	send := func(cmd string) {
		t.Helper()
		if _, werr := fmt.Fprintf(conn, "%s\r\n", cmd); werr != nil {
			t.Fatalf("write %q: %v", cmd, werr)
		}
	}
	waitFor := func(prefix string) {
		t.Helper()
		for {
			line, rerr := r.ReadString('\n')
			if rerr != nil {
				t.Fatalf("waiting for %q: %v", prefix, rerr)
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

	// Session-manager "restarts": all tokens die, and a message is
	// delivered while the old mail-session is gone. The delivery
	// notification still arrives over Redis (a separate transport).
	sm.invalidateTokens()
	sm.addMessage(2)
	mr.Publish(notify.MailChannel("alice@test.local"), "INBOX")

	// The IDLE client must receive the untagged EXISTS for the message
	// without reconnecting.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = conn.SetReadDeadline(deadline)
		line, rerr := r.ReadString('\n')
		if rerr != nil {
			t.Fatalf("waiting for * 2 EXISTS after recovery: %v", rerr)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "* 2 EXISTS") {
			break
		}
	}
	if got := sm.loginCount(); got != 2 {
		t.Errorf("login count = %d, want 2 (transparent re-login)", got)
	}

	// End the IDLE and log out cleanly: killing the socket mid-IDLE trips a
	// separate, pre-existing teardown race between Session.Close and the
	// Idle goroutine (#202), which is not this test's subject.
	send("DONE")
	waitFor("a3 OK")
	send("a4 LOGOUT")
	waitFor("a4 OK")
}
