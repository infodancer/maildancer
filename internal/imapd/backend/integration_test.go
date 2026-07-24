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

// mockIntegrationSession implements SessionService for integration tests.
type mockIntegrationSession struct {
	smpb.UnimplementedSessionServiceServer
}

func (m *mockIntegrationSession) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	if req.Username == "alice@test.local" && req.Password == "testpass" {
		return &smpb.LoginResponse{
			SessionToken: "integration-tok",
			Mailbox:      "alice@test.local",
		}, nil
	}
	return nil, fmt.Errorf("bad credentials")
}

func (m *mockIntegrationSession) Logout(_ context.Context, _ *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	return &smpb.LogoutResponse{}, nil
}

// mockIntegrationMailbox implements MailboxService for integration tests.
type mockIntegrationMailbox struct {
	pb.UnimplementedMailboxServiceServer
}

func (m *mockIntegrationMailbox) List(_ context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	return &pb.ListResponse{
		Messages: []*pb.MessageInfo{
			{Uid: 1, Size: 100, Flags: []string{}},
		},
	}, nil
}

func (m *mockIntegrationMailbox) Stat(_ context.Context, _ *pb.StatRequest) (*pb.StatResponse, error) {
	return &pb.StatResponse{Count: 1, TotalBytes: 100}, nil
}

func (m *mockIntegrationMailbox) UIDValidity(_ context.Context, _ *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	return &pb.UIDValidityResponse{UidValidity: 1, UidNext: 2}, nil
}

// mockIntegrationFolder implements FolderService for integration tests.
type mockIntegrationFolder struct {
	pb.UnimplementedFolderServiceServer
}

func (m *mockIntegrationFolder) ListFolders(_ context.Context, _ *pb.ListFoldersRequest) (*pb.ListFoldersResponse, error) {
	return &pb.ListFoldersResponse{Folders: []string{"INBOX", "Sent", "Drafts", "Junk", "Trash"}}, nil
}

func (m *mockIntegrationFolder) CreateFolder(_ context.Context, _ *pb.CreateFolderRequest) (*pb.CreateFolderResponse, error) {
	return &pb.CreateFolderResponse{}, nil
}

func TestStack_IMAPFullStack(t *testing.T) {
	// Start a mock gRPC session-manager server.
	dir := t.TempDir()
	sock := filepath.Join(dir, "sm.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, &mockIntegrationSession{})
	pb.RegisterMailboxServiceServer(srv, &mockIntegrationMailbox{})
	pb.RegisterFolderServiceServer(srv, &mockIntegrationFolder{})

	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop() })

	// The test owns the TCP listener; each accepted connection is served
	// through Stack.ServeConn -- the exact code path the forked
	// protocol-handler subprocess runs (#179). Fork/exec itself is covered
	// by forkperconn_test.go.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()
	addr := tcpLn.Addr().String()

	// Build config. No listeners: the Stack serves individual connections.
	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = nil

	stack, err := backend.NewStack(backend.StackConfig{
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	defer stack.Close() //nolint:errcheck // cleanup path; nothing actionable if Close fails here

	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = stack.ServeConn(c, config.ModeImap) }()
		}
	}()

	// Connect and run IMAP conversation.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	r := bufio.NewReader(conn)

	// Read greeting.
	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}
	t.Logf("S: %s", strings.TrimRight(greeting, "\r\n"))

	// Helper: send a command and collect responses until the tagged response.
	sendCmd := func(tag, cmd string) []string {
		t.Helper()
		_, werr := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		if werr != nil {
			t.Fatalf("write %s: %v", tag, werr)
		}
		t.Logf("C: %s %s", tag, cmd)
		var lines []string
		for {
			line, rerr := r.ReadString('\n')
			if rerr != nil {
				t.Fatalf("read response for %s: %v", tag, rerr)
			}
			line = strings.TrimRight(line, "\r\n")
			t.Logf("S: %s", line)
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		return lines
	}

	// LOGIN
	loginResp := sendCmd("A1", "LOGIN alice@test.local testpass")
	tagged := loginResp[len(loginResp)-1]
	if !strings.HasPrefix(tagged, "A1 OK") {
		t.Fatalf("LOGIN failed: %s", tagged)
	}

	// SELECT INBOX
	selectResp := sendCmd("A2", "SELECT INBOX")
	tagged = selectResp[len(selectResp)-1]
	if !strings.HasPrefix(tagged, "A2 OK") {
		t.Fatalf("SELECT INBOX failed: %s", tagged)
	}

	// Find the EXISTS line and assert 1 message.
	var existsLine string
	for _, line := range selectResp {
		if strings.Contains(line, "EXISTS") {
			existsLine = line
			break
		}
	}
	if existsLine == "" {
		t.Fatalf("no EXISTS line in SELECT response: %v", selectResp)
	}
	if !strings.HasPrefix(existsLine, "* 1 EXISTS") {
		t.Fatalf("expected '* 1 EXISTS', got %q", existsLine)
	}

	// LOGOUT
	sendCmd("A3", "LOGOUT")
}
