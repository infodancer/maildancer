//go:build integration

package backend_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
)

// mockDedupMailbox serves two messages -- UID 1 (unflagged) and UID 2
// (\Deleted) -- and implements the Move/SetFlags/Expunge RPCs the MOVE and
// EXPUNGE command paths use. It is deliberately stateless: each test case uses
// a fresh connection (hence a fresh SELECT and mailbox tracker), so the store
// never needs to reflect prior mutations.
type mockDedupMailbox struct {
	pb.UnimplementedMailboxServiceServer
}

func (m *mockDedupMailbox) List(_ context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	return &pb.ListResponse{
		Messages: []*pb.MessageInfo{
			{Uid: 1, Size: 100, Flags: []string{}},
			{Uid: 2, Size: 120, Flags: []string{"\\Deleted"}},
		},
	}, nil
}

func (m *mockDedupMailbox) Stat(_ context.Context, _ *pb.StatRequest) (*pb.StatResponse, error) {
	return &pb.StatResponse{Count: 2, TotalBytes: 220}, nil
}

func (m *mockDedupMailbox) UIDValidity(_ context.Context, _ *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	return &pb.UIDValidityResponse{UidValidity: 1, UidNext: 3}, nil
}

func (m *mockDedupMailbox) Move(_ context.Context, _ *pb.MoveRequest) (*pb.MoveResponse, error) {
	return &pb.MoveResponse{NewUid: 42}, nil
}

func (m *mockDedupMailbox) SetFlags(_ context.Context, _ *pb.SetFlagsRequest) (*pb.SetFlagsResponse, error) {
	return &pb.SetFlagsResponse{}, nil
}

func (m *mockDedupMailbox) Expunge(_ context.Context, _ *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	return &pb.ExpungeResponse{}, nil
}

// TestStack_ExpungeResponsesNotDuplicated is the regression test for issue #132:
// UID MOVE and EXPUNGE must each emit exactly one "* n EXPUNGE" per message, not
// two. The duplicate arose because the handlers wrote the EXPUNGE directly *and*
// queued it on the tracker, which go-imap's post-command poll then re-emitted.
func TestStack_ExpungeResponsesNotDuplicated(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sm.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, &mockIntegrationSession{})
	pb.RegisterMailboxServiceServer(srv, &mockDedupMailbox{})
	pb.RegisterFolderServiceServer(srv, &mockIntegrationFolder{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop() })

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	addr := tcpLn.Addr().String()
	tcpLn.Close()

	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModeImap}}

	stack, err := backend.NewStack(backend.StackConfig{Config: cfg})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	defer stack.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := stack.Run(ctx); err != nil {
			t.Logf("stack.Run: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// connectSelect dials, logs in, and SELECTs INBOX, returning a sendCmd bound
	// to the connection. Each call is a fresh connection (fresh mailbox tracker).
	connectSelect := func(t *testing.T) func(tag, cmd string) []string {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		if _, err := r.ReadString('\n'); err != nil { // greeting
			t.Fatalf("read greeting: %v", err)
		}

		sendCmd := func(tag, cmd string) []string {
			t.Helper()
			if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
				t.Fatalf("write %s: %v", tag, err)
			}
			var lines []string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					t.Fatalf("read response for %s: %v", tag, err)
				}
				line = strings.TrimRight(line, "\r\n")
				lines = append(lines, line)
				if strings.HasPrefix(line, tag+" ") {
					return lines
				}
			}
		}

		if resp := sendCmd("A1", "LOGIN alice@test.local testpass"); !strings.HasPrefix(resp[len(resp)-1], "A1 OK") {
			t.Fatalf("LOGIN failed: %s", resp[len(resp)-1])
		}
		if resp := sendCmd("A2", "SELECT INBOX"); !strings.HasPrefix(resp[len(resp)-1], "A2 OK") {
			t.Fatalf("SELECT failed: %s", resp[len(resp)-1])
		}
		return sendCmd
	}

	countExpunge := func(lines []string) int {
		n := 0
		for _, l := range lines {
			// Untagged EXPUNGE response: "* <seq> EXPUNGE".
			if strings.HasPrefix(l, "* ") && strings.HasSuffix(l, " EXPUNGE") {
				n++
			}
		}
		return n
	}

	t.Run("UID MOVE emits one EXPUNGE", func(t *testing.T) {
		sendCmd := connectSelect(t)
		resp := sendCmd("A3", "UID MOVE 1 Junk")
		if !strings.HasPrefix(resp[len(resp)-1], "A3 OK") {
			t.Fatalf("UID MOVE failed: %v", resp)
		}
		if got := countExpunge(resp); got != 1 {
			t.Errorf("UID MOVE emitted %d EXPUNGE responses, want exactly 1: %v", got, resp)
		}
	})

	t.Run("EXPUNGE emits one EXPUNGE", func(t *testing.T) {
		sendCmd := connectSelect(t)
		resp := sendCmd("A3", "EXPUNGE")
		if !strings.HasPrefix(resp[len(resp)-1], "A3 OK") {
			t.Fatalf("EXPUNGE failed: %v", resp)
		}
		if got := countExpunge(resp); got != 1 {
			t.Errorf("EXPUNGE emitted %d EXPUNGE responses, want exactly 1: %v", got, resp)
		}
	})
}
