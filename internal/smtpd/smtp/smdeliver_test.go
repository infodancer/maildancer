package smtp

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"google.golang.org/grpc"
)

// mockDeliveryServer implements DeliveryServiceServer for tests.
type mockDeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer

	// response to return
	result            pb.DeliverResult
	temporary         bool
	reason            string
	redirectAddresses []string

	// captured values
	metadata *pb.DeliverMetadata
	body     []byte
}

func (s *mockDeliveryServer) Deliver(stream grpc.ClientStreamingServer[pb.DeliverRequest, pb.DeliverResponse]) error {
	var body bytes.Buffer

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch p := req.Payload.(type) {
		case *pb.DeliverRequest_Metadata:
			s.metadata = p.Metadata
		case *pb.DeliverRequest_Data:
			body.Write(p.Data)
		}
	}

	s.body = body.Bytes()

	return stream.SendAndClose(&pb.DeliverResponse{
		Result:            s.result,
		Temporary:         s.temporary,
		Reason:            s.reason,
		RedirectAddresses: s.redirectAddresses,
	})
}

// startMockServer starts a gRPC server on a temp unix socket and returns the
// socket path.
func startMockServer(t *testing.T, srv *mockDeliveryServer) string {
	t.Helper()

	socketPath := t.TempDir() + "/test.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, srv)

	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	return socketPath
}

func TestSessionManagerDelivery_Delivered(t *testing.T) {
	mock := &mockDeliveryServer{
		result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
	}
	socketPath := startMockServer(t, mock)

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	body := "Subject: Test\r\n\r\nHello, world!\r\n"
	receivedTime := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)

	err = agent.Deliver(context.Background(),
		"sender@example.com", "user@example.com",
		"192.168.1.1", "mail.example.com",
		receivedTime, strings.NewReader(body))
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}

	// Verify metadata was passed correctly.
	if mock.metadata == nil {
		t.Fatal("no metadata received")
	}
	if mock.metadata.Sender != "sender@example.com" {
		t.Errorf("sender = %q, want %q", mock.metadata.Sender, "sender@example.com")
	}
	if mock.metadata.Recipient != "user@example.com" {
		t.Errorf("recipient = %q, want %q", mock.metadata.Recipient, "user@example.com")
	}
	if mock.metadata.ClientIp != "192.168.1.1" {
		t.Errorf("client_ip = %q, want %q", mock.metadata.ClientIp, "192.168.1.1")
	}
	if mock.metadata.ClientHostname != "mail.example.com" {
		t.Errorf("client_hostname = %q, want %q", mock.metadata.ClientHostname, "mail.example.com")
	}
	if mock.metadata.ReceivedTime == "" {
		t.Error("received_time is empty")
	}

	// Verify body was streamed.
	if string(mock.body) != body {
		t.Errorf("body = %q, want %q", string(mock.body), body)
	}
}

func TestSessionManagerDelivery_Rejected(t *testing.T) {
	mock := &mockDeliveryServer{
		result:    pb.DeliverResult_DELIVER_RESULT_REJECTED,
		temporary: false,
		reason:    "mailbox full",
	}
	socketPath := startMockServer(t, mock)

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	err = agent.Deliver(context.Background(),
		"sender@example.com", "user@example.com",
		"", "", time.Time{}, strings.NewReader("test"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("error = %q, want 550 code", err.Error())
	}
	if !strings.Contains(err.Error(), "mailbox full") {
		t.Errorf("error = %q, want reason 'mailbox full'", err.Error())
	}
}

func TestSessionManagerDelivery_RejectedTemporary(t *testing.T) {
	mock := &mockDeliveryServer{
		result:    pb.DeliverResult_DELIVER_RESULT_REJECTED,
		temporary: true,
		reason:    "try again later",
	}
	socketPath := startMockServer(t, mock)

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	err = agent.Deliver(context.Background(),
		"sender@example.com", "user@example.com",
		"", "", time.Time{}, strings.NewReader("test"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "451") {
		t.Errorf("error = %q, want 451 code", err.Error())
	}
}

func TestSessionManagerDelivery_Redirected(t *testing.T) {
	mock := &mockDeliveryServer{
		result:            pb.DeliverResult_DELIVER_RESULT_REDIRECTED,
		redirectAddresses: []string{"forward@other.com", "alias@other.com"},
	}
	socketPath := startMockServer(t, mock)

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	err = agent.Deliver(context.Background(),
		"sender@example.com", "user@example.com",
		"", "", time.Time{}, strings.NewReader("test"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	redirectErr, ok := err.(*RedirectError)
	if !ok {
		t.Fatalf("error type = %T, want *RedirectError", err)
	}
	if len(redirectErr.Addresses) != 2 {
		t.Errorf("redirect addresses = %v, want 2 addresses", redirectErr.Addresses)
	}
	if redirectErr.Addresses[0] != "forward@other.com" {
		t.Errorf("redirect[0] = %q, want %q", redirectErr.Addresses[0], "forward@other.com")
	}
}

func TestSessionManagerDelivery_LargeMessage(t *testing.T) {
	mock := &mockDeliveryServer{
		result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
	}
	socketPath := startMockServer(t, mock)

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// 256KB message — forces multiple 64KB chunks.
	largeBody := strings.Repeat("X", 256*1024)

	err = agent.Deliver(context.Background(),
		"sender@example.com", "user@example.com",
		"", "", time.Time{}, strings.NewReader(largeBody))
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}

	if len(mock.body) != 256*1024 {
		t.Errorf("body size = %d, want %d", len(mock.body), 256*1024)
	}
}

func TestNewSessionManagerDeliveryAgent_SocketRequired(t *testing.T) {
	_, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "socket or address required") {
		t.Errorf("error = %q, want 'socket or address required'", err.Error())
	}
}

func TestSessionManagerConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.SessionManagerConfig
		want bool
	}{
		{"empty", config.SessionManagerConfig{}, false},
		{"socket", config.SessionManagerConfig{Socket: "/tmp/test.sock"}, true},
		{"address", config.SessionManagerConfig{Address: "localhost:9443"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionManagerConfig_LoadFromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.toml"
	tomlContent := `
[session-manager]
socket = "/run/session-manager.sock"

[smtpd]
hostname = "mail.example.com"

[[smtpd.listeners]]
address = ":25"
mode = "smtp"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SessionManager.Socket != "/run/session-manager.sock" {
		t.Errorf("SessionManager.Socket = %q, want %q", cfg.SessionManager.Socket, "/run/session-manager.sock")
	}
	if !cfg.SessionManager.IsEnabled() {
		t.Error("SessionManager should be enabled")
	}
}

func TestSessionManagerConfig_LoadFromTOML_mTLS(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.toml"
	tomlContent := `
[session-manager]
address = "session-manager:9443"
ca_cert = "/etc/mail/certs/ca.crt"
client_cert = "/etc/mail/certs/smtpd.crt"
client_key = "/etc/mail/certs/smtpd.key"

[smtpd]
hostname = "mail.example.com"

[[smtpd.listeners]]
address = ":25"
mode = "smtp"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SessionManager.Address != "session-manager:9443" {
		t.Errorf("Address = %q, want %q", cfg.SessionManager.Address, "session-manager:9443")
	}
	if cfg.SessionManager.CACert != "/etc/mail/certs/ca.crt" {
		t.Errorf("CACert = %q, want %q", cfg.SessionManager.CACert, "/etc/mail/certs/ca.crt")
	}
	if cfg.SessionManager.ClientCert != "/etc/mail/certs/smtpd.crt" {
		t.Errorf("ClientCert = %q, want %q", cfg.SessionManager.ClientCert, "/etc/mail/certs/smtpd.crt")
	}
	if cfg.SessionManager.ClientKey != "/etc/mail/certs/smtpd.key" {
		t.Errorf("ClientKey = %q, want %q", cfg.SessionManager.ClientKey, "/etc/mail/certs/smtpd.key")
	}
}
