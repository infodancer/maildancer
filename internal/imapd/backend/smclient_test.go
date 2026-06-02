package backend

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/infodancer/maildancer/internal/imapd/config"
)

// --- Mock services ---

type mockSessionService struct {
	smpb.UnimplementedSessionServiceServer
	loginUser  string
	loginPass  string
	loginToken string
	loginMbox  string
	loginErr   error
	loggedOut  bool
}

func (m *mockSessionService) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	if m.loginErr != nil {
		return nil, m.loginErr
	}
	if req.Username != m.loginUser || req.Password != m.loginPass {
		return nil, status.Error(codes.Unauthenticated, "bad credentials")
	}
	return &smpb.LoginResponse{
		SessionToken: m.loginToken,
		Mailbox:      m.loginMbox,
	}, nil
}

func (m *mockSessionService) Logout(_ context.Context, _ *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	m.loggedOut = true
	return &smpb.LogoutResponse{}, nil
}

type mockMailboxService struct {
	pb.UnimplementedMailboxServiceServer
	lastToken string
}

func (m *mockMailboxService) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.ListResponse{
		Messages: []*pb.MessageInfo{
			{Uid: 1, Size: 100},
			{Uid: 2, Size: 200},
		},
	}, nil
}

func (m *mockMailboxService) Stat(ctx context.Context, _ *pb.StatRequest) (*pb.StatResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.StatResponse{Count: 2, TotalBytes: 300}, nil
}

func (m *mockMailboxService) UIDValidity(ctx context.Context, _ *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.UIDValidityResponse{UidValidity: 42}, nil
}

func (m *mockMailboxService) Copy(ctx context.Context, _ *pb.CopyRequest) (*pb.CopyResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.CopyResponse{NewUid: 101}, nil
}

func (m *mockMailboxService) Move(ctx context.Context, _ *pb.MoveRequest) (*pb.MoveResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.MoveResponse{NewUid: 201}, nil
}

func (m *mockMailboxService) SetFlags(ctx context.Context, _ *pb.SetFlagsRequest) (*pb.SetFlagsResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.SetFlagsResponse{}, nil
}

func (m *mockMailboxService) Expunge(ctx context.Context, _ *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.ExpungeResponse{}, nil
}

func (m *mockMailboxService) Rescan(ctx context.Context, _ *pb.RescanRequest) (*pb.RescanResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.RescanResponse{
		NewMessages: []*pb.MessageInfo{
			{Uid: 99, Size: 50},
		},
	}, nil
}

type mockFolderService struct {
	pb.UnimplementedFolderServiceServer
	lastToken string
}

func (m *mockFolderService) ListFolders(ctx context.Context, _ *pb.ListFoldersRequest) (*pb.ListFoldersResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.ListFoldersResponse{Folders: []string{"Sent", "Junk", "Drafts"}}, nil
}

func (m *mockFolderService) CreateFolder(ctx context.Context, _ *pb.CreateFolderRequest) (*pb.CreateFolderResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.CreateFolderResponse{}, nil
}

func (m *mockFolderService) DeleteFolder(ctx context.Context, _ *pb.DeleteFolderRequest) (*pb.DeleteFolderResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.DeleteFolderResponse{}, nil
}

func (m *mockFolderService) RenameFolder(ctx context.Context, _ *pb.RenameFolderRequest) (*pb.RenameFolderResponse, error) {
	m.lastToken = tokenFromCtx(ctx)
	return &pb.RenameFolderResponse{}, nil
}

func tokenFromCtx(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("session-token")
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// startTestServer starts a gRPC server on a temp unix socket and returns
// the client, mock services, and a cleanup function.
func startTestServer(t *testing.T) (*SessionManagerClient, *mockSessionService, *mockMailboxService, *mockFolderService) {
	t.Helper()

	dir := t.TempDir()
	sock := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()
	sessMock := &mockSessionService{
		loginUser:  "user@example.com",
		loginPass:  "secret",
		loginToken: "tok123",
		loginMbox:  "user@example.com",
	}
	mboxMock := &mockMailboxService{}
	folderMock := &mockFolderService{}

	smpb.RegisterSessionServiceServer(srv, sessMock)
	pb.RegisterMailboxServiceServer(srv, mboxMock)
	pb.RegisterFolderServiceServer(srv, folderMock)

	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop() })

	client, err := NewSessionManagerClient(config.SessionManagerConfig{Socket: sock}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client, sessMock, mboxMock, folderMock
}

// --- Tests ---

func TestSMClient_LoginLogout(t *testing.T) {
	client, sessMock, _, _ := startTestServer(t)
	ctx := context.Background()

	token, mailbox, err := client.Login(ctx, "user@example.com", "secret")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token != "tok123" {
		t.Errorf("token = %q, want %q", token, "tok123")
	}
	if mailbox != "user@example.com" {
		t.Errorf("mailbox = %q, want %q", mailbox, "user@example.com")
	}

	if err := client.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !sessMock.loggedOut {
		t.Error("expected logout to be called")
	}
}

func TestSMClient_LoginFailure(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	_, _, err := client.Login(ctx, "user@example.com", "wrong")
	if err == nil {
		t.Fatal("expected login error, got nil")
	}
}

func TestSMClient_SessionTokenInMetadata(t *testing.T) {
	client, _, mboxMock, _ := startTestServer(t)
	ctx := context.Background()

	token, _, err := client.Login(ctx, "user@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ListMessages(ctx, token, "INBOX")
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if mboxMock.lastToken != token {
		t.Errorf("token in metadata = %q, want %q", mboxMock.lastToken, token)
	}
}

func TestSMClient_ListMessages(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	msgs, err := client.ListMessages(ctx, token, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Errorf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Uid != 1 || msgs[1].Uid != 2 {
		t.Errorf("unexpected message UIDs: %v", msgs)
	}
}

func TestSMClient_StatMailbox(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	count, totalBytes, err := client.StatMailbox(ctx, token, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if totalBytes != 300 {
		t.Errorf("totalBytes = %d, want 300", totalBytes)
	}
}

func TestSMClient_FolderOperations(t *testing.T) {
	client, _, _, folderMock := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")

	// ListFolders
	folders, err := client.ListFolders(ctx, token)
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(folders) != 3 {
		t.Errorf("got %d folders, want 3", len(folders))
	}
	if folderMock.lastToken != token {
		t.Errorf("folder token = %q, want %q", folderMock.lastToken, token)
	}

	// CreateFolder
	if err := client.CreateFolder(ctx, token, "Archive"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// RenameFolder
	if err := client.RenameFolder(ctx, token, "Archive", "Old"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}

	// DeleteFolder
	if err := client.DeleteFolder(ctx, token, "Old"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
}

func TestSMClient_CopyAndMove(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")

	newUID, err := client.CopyMessage(ctx, token, "INBOX", 1, "Sent")
	if err != nil {
		t.Fatalf("CopyMessage: %v", err)
	}
	if newUID != 101 {
		t.Errorf("copy UID = %d, want 101", newUID)
	}

	moveUID, err := client.MoveMessage(ctx, token, "INBOX", 1, "Junk")
	if err != nil {
		t.Fatalf("MoveMessage: %v", err)
	}
	if moveUID != 201 {
		t.Errorf("move UID = %d, want 201", moveUID)
	}
}

func TestSMClient_UIDValidity(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	val, err := client.UIDValidity(ctx, token, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if val != 42 {
		t.Errorf("UIDValidity = %d, want 42", val)
	}
}

func TestSMClient_ExpungeAndDelete(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")

	if err := client.DeleteMessage(ctx, token, "INBOX", 1); err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}

	if err := client.ExpungeMailbox(ctx, token, "INBOX"); err != nil {
		t.Fatalf("ExpungeMailbox: %v", err)
	}
}

func TestSMClient_Rescan(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	msgs, err := client.RescanFolder(ctx, token, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Errorf("got %d new messages, want 1", len(msgs))
	}
	if msgs[0].Uid != 99 {
		t.Errorf("new message UID = %d, want 99", msgs[0].Uid)
	}
}

func TestSMClient_SocketRequired(t *testing.T) {
	_, err := NewSessionManagerClient(config.SessionManagerConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for empty config, got nil")
	}
}

func TestSessionManagerConfig_IsEnabled(t *testing.T) {
	cfg := config.SessionManagerConfig{}
	if cfg.IsEnabled() {
		t.Error("IsEnabled() = true for empty config")
	}

	cfg.Socket = "/tmp/test.sock"
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false with socket set")
	}

	cfg = config.SessionManagerConfig{Address: "localhost:8443"}
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false with address set")
	}
}

func TestSessionManagerConfig_LoadFromTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "imapd.toml")
	content := `
[session-manager]
socket = "/var/run/session-manager.sock"

[imapd]
hostname = "imap.example.com"

[[imapd.listeners]]
address = ":143"
mode = "imap"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionManager.Socket != "/var/run/session-manager.sock" {
		t.Errorf("socket = %q, want %q", cfg.SessionManager.Socket, "/var/run/session-manager.sock")
	}
	if !cfg.SessionManager.IsEnabled() {
		t.Error("IsEnabled() = false after TOML load")
	}
}

func TestSessionManagerConfig_mTLSMissingCert(t *testing.T) {
	_, err := NewSessionManagerClient(config.SessionManagerConfig{
		Address: "localhost:8443",
		CACert:  "/nonexistent/ca.pem",
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing CA cert, got nil")
	}
}

// --- Store adapter tests ---

func TestSMStore_ListAndStat(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	msgs, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("List got %d messages, want 2", len(msgs))
	}

	count, totalBytes, err := store.Stat(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 2 || totalBytes != 300 {
		t.Errorf("Stat = (%d, %d), want (2, 300)", count, totalBytes)
	}
}

func TestSMStore_FolderOperations(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	folders, err := store.ListFolders(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(folders) != 3 {
		t.Errorf("got %d folders, want 3", len(folders))
	}

	if err := store.CreateFolder(ctx, "", "Archive"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	if err := store.RenameFolder(ctx, "", "Archive", "Old"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}

	if err := store.DeleteFolder(ctx, "", "Old"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
}

func TestSMStore_MoveMessage(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	newUID, err := store.MoveMessage(ctx, "", "INBOX", 1, "Junk")
	if err != nil {
		t.Fatalf("MoveMessage: %v", err)
	}
	if newUID != 201 {
		t.Errorf("MoveMessage UID = %d, want 201", newUID)
	}
}

func TestSMStore_Rescan(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	// ListInFolder sets selectedFolder
	_, err := store.ListInFolder(ctx, "", "Sent")
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := store.Rescan()
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("Rescan got %d messages, want 1", len(msgs))
	}
}

func TestSMStore_Close_CallsLogout(t *testing.T) {
	client, sessMock, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !sessMock.loggedOut {
		t.Error("expected Logout to be called on Close")
	}
}

func TestSMStore_UIDValidity(t *testing.T) {
	client, _, _, _ := startTestServer(t)
	ctx := context.Background()

	token, _, _ := client.Login(ctx, "user@example.com", "secret")
	store := newSessionManagerStore(client, token)

	val, err := store.UIDValidity(ctx, "", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if val != 42 {
		t.Errorf("UIDValidity = %d, want 42", val)
	}
}
