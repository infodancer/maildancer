package pop3

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockSessionService is a test implementation of SessionService.
type mockSessionService struct {
	smpb.UnimplementedSessionServiceServer
	loginFunc  func(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error)
	logoutFunc func(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error)
}

func (m *mockSessionService) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	if m.loginFunc != nil {
		return m.loginFunc(ctx, req)
	}
	return &smpb.LoginResponse{
		SessionToken: "test-token-123",
		Mailbox:      req.Username,
	}, nil
}

func (m *mockSessionService) Logout(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	if m.logoutFunc != nil {
		return m.logoutFunc(ctx, req)
	}
	return &smpb.LogoutResponse{}, nil
}

// mockMailboxService is a test implementation of MailboxService.
type mockMailboxService struct {
	pb.UnimplementedMailboxServiceServer
	listFunc    func(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error)
	statFunc    func(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error)
	fetchFunc   func(req *pb.FetchRequest, stream grpc.ServerStreamingServer[pb.FetchResponse]) error
	deleteFunc  func(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error)
	expungeFunc func(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error)
}

func (m *mockMailboxService) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, req)
	}
	return &pb.ListResponse{
		Messages: []*pb.MessageInfo{
			{Uid: "msg1", Size: 1024},
			{Uid: "msg2", Size: 2048},
		},
	}, nil
}

func (m *mockMailboxService) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	if m.statFunc != nil {
		return m.statFunc(ctx, req)
	}
	return &pb.StatResponse{Count: 2, TotalBytes: 3072}, nil
}

func (m *mockMailboxService) Fetch(req *pb.FetchRequest, stream grpc.ServerStreamingServer[pb.FetchResponse]) error {
	if m.fetchFunc != nil {
		return m.fetchFunc(req, stream)
	}
	return stream.Send(&pb.FetchResponse{Data: []byte("Subject: test\r\n\r\nHello")})
}

func (m *mockMailboxService) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, req)
	}
	return &pb.DeleteResponse{}, nil
}

func (m *mockMailboxService) Expunge(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	if m.expungeFunc != nil {
		return m.expungeFunc(ctx, req)
	}
	return &pb.ExpungeResponse{}, nil
}

// startTestServer starts a gRPC server on a unix socket and returns the socket path
// and a cleanup function.
func startTestServer(t *testing.T, sessionSvc *mockSessionService, mailboxSvc *mockMailboxService) (string, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, sessionSvc)
	pb.RegisterMailboxServiceServer(srv, mailboxSvc)

	go func() { _ = srv.Serve(ln) }()

	return socketPath, func() {
		srv.GracefulStop()
		_ = os.RemoveAll(tmpDir)
	}
}

func TestSessionManagerClient_LoginLogout(t *testing.T) {
	sessionSvc := &mockSessionService{}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	token, mailbox, err := client.Login(ctx, "alice@example.com", "secret")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("token = %q, want %q", token, "test-token-123")
	}
	if mailbox != "alice@example.com" {
		t.Errorf("mailbox = %q, want %q", mailbox, "alice@example.com")
	}

	if err := client.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

func TestSessionManagerClient_LoginFailure(t *testing.T) {
	sessionSvc := &mockSessionService{
		loginFunc: func(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
			return nil, status.Error(codes.Unauthenticated, "bad password")
		},
	}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, _, err = client.Login(context.Background(), "alice@example.com", "wrong")
	if err == nil {
		t.Fatal("Login should have failed")
	}
}

func TestSessionManagerClient_ListMessages(t *testing.T) {
	sessionSvc := &mockSessionService{}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	msgs, err := client.ListMessages(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Uid != "msg1" || msgs[0].Size != 1024 {
		t.Errorf("msg[0] = %+v, want uid=msg1 size=1024", msgs[0])
	}
}

func TestSessionManagerClient_SessionTokenInMetadata(t *testing.T) {
	var capturedToken string
	mailboxSvc := &mockMailboxService{
		listFunc: func(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
			md, ok := metadata.FromIncomingContext(ctx)
			if ok {
				vals := md.Get("session-token")
				if len(vals) > 0 {
					capturedToken = vals[0]
				}
			}
			return &pb.ListResponse{}, nil
		},
	}
	sessionSvc := &mockSessionService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.ListMessages(context.Background(), "my-secret-token", "")
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if capturedToken != "my-secret-token" {
		t.Errorf("session-token metadata = %q, want %q", capturedToken, "my-secret-token")
	}
}

func TestSessionManagerClient_StatMailbox(t *testing.T) {
	sessionSvc := &mockSessionService{}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	count, totalBytes, err := client.StatMailbox(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("StatMailbox: %v", err)
	}
	if count != 2 || totalBytes != 3072 {
		t.Errorf("Stat = (%d, %d), want (2, 3072)", count, totalBytes)
	}
}

func TestSessionManagerClient_FetchMessage(t *testing.T) {
	sessionSvc := &mockSessionService{}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	rc, err := client.FetchMessage(context.Background(), "tok", "", "msg1")
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "Subject: test\r\n\r\nHello" {
		t.Errorf("body = %q, want %q", string(data), "Subject: test\r\n\r\nHello")
	}
}

func TestSessionManagerClient_DeleteAndExpunge(t *testing.T) {
	var deletedUID string
	var expungedFolder string
	mailboxSvc := &mockMailboxService{
		deleteFunc: func(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
			deletedUID = req.Uid
			return &pb.DeleteResponse{}, nil
		},
		expungeFunc: func(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
			expungedFolder = req.Folder
			return &pb.ExpungeResponse{}, nil
		},
	}
	sessionSvc := &mockSessionService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	if err := client.DeleteMessage(ctx, "tok", "msg1"); err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}
	if deletedUID != "msg1" {
		t.Errorf("deleted UID = %q, want %q", deletedUID, "msg1")
	}

	if err := client.ExpungeMailbox(ctx, "tok", "INBOX"); err != nil {
		t.Fatalf("ExpungeMailbox: %v", err)
	}
	if expungedFolder != "INBOX" {
		t.Errorf("expunged folder = %q, want %q", expungedFolder, "INBOX")
	}
}

func TestSessionManagerClient_SocketRequired(t *testing.T) {
	_, err := NewSessionManagerClient(config.SessionManagerConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestSessionManagerConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.SessionManagerConfig
		enabled bool
	}{
		{"empty", config.SessionManagerConfig{}, false},
		{"socket", config.SessionManagerConfig{Socket: "/tmp/sm.sock"}, true},
		{"address", config.SessionManagerConfig{Address: "localhost:9443"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.enabled {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.enabled)
			}
		})
	}
}

func TestSessionManagerConfig_LoadFromTOML(t *testing.T) {
	tmpDir := t.TempDir()

	// Test unix socket config
	cfgPath := tmpDir + "/socket.toml"
	_ = os.WriteFile(cfgPath, []byte(`
[session-manager]
socket = "/var/run/session-manager.sock"
`), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionManager.Socket != "/var/run/session-manager.sock" {
		t.Errorf("Socket = %q, want %q", cfg.SessionManager.Socket, "/var/run/session-manager.sock")
	}

	// Test mTLS config
	cfgPath = tmpDir + "/mtls.toml"
	_ = os.WriteFile(cfgPath, []byte(`
[session-manager]
address = "session-manager:9443"
ca_cert = "/etc/mail/certs/ca.crt"
client_cert = "/etc/mail/certs/pop3d.crt"
client_key = "/etc/mail/certs/pop3d.key"
`), 0644)

	cfg, err = config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionManager.Address != "session-manager:9443" {
		t.Errorf("Address = %q, want %q", cfg.SessionManager.Address, "session-manager:9443")
	}
	if cfg.SessionManager.CACert != "/etc/mail/certs/ca.crt" {
		t.Errorf("CACert = %q, want %q", cfg.SessionManager.CACert, "/etc/mail/certs/ca.crt")
	}
}

func TestNewSessionManagerClient_mTLSMissingCert(t *testing.T) {
	_, err := NewSessionManagerClient(config.SessionManagerConfig{
		Address:    "localhost:9443",
		CACert:     "/nonexistent/ca.crt",
		ClientCert: "/nonexistent/client.crt",
		ClientKey:  "/nonexistent/client.key",
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing mTLS certs")
	}
}

// Test the store adapter.
func TestSessionManagerStore_ListAndStat(t *testing.T) {
	sessionSvc := &mockSessionService{}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	client, err := NewSessionManagerClient(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	store := newSessionManagerStore(client, "test-token")
	ctx := context.Background()

	// Test List
	msgs, err := store.List(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].UID != "msg1" || msgs[0].Size != 1024 {
		t.Errorf("msg[0] = %+v", msgs[0])
	}

	// Test Stat
	count, totalBytes, err := store.Stat(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 2 || totalBytes != 3072 {
		t.Errorf("Stat = (%d, %d), want (2, 3072)", count, totalBytes)
	}
}

func TestSessionManagerStore_Close_CallsLogout(t *testing.T) {
	var logoutCalled bool
	var logoutToken string
	sessionSvc := &mockSessionService{
		logoutFunc: func(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
			logoutCalled = true
			logoutToken = req.SessionToken
			return &smpb.LogoutResponse{}, nil
		},
	}
	mailboxSvc := &mockMailboxService{}
	socketPath, cleanup := startTestServer(t, sessionSvc, mailboxSvc)
	defer cleanup()

	// Use a direct gRPC connection since we need to bypass NewSessionManagerClient's lifecycle.
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := &SessionManagerClient{
		conn:    conn,
		session: smpb.NewSessionServiceClient(conn),
		mailbox: pb.NewMailboxServiceClient(conn),
	}

	store := newSessionManagerStore(client, "logout-test-token")
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !logoutCalled {
		t.Error("Logout was not called")
	}
	if logoutToken != "logout-test-token" {
		t.Errorf("logout token = %q, want %q", logoutToken, "logout-test-token")
	}

	_ = client.Close()
}
