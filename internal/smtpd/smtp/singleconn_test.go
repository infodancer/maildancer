package smtp_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
	"google.golang.org/grpc"
)

// newSingleConnEnv creates a minimal Server (no listener started) for use
// with RunSingleConn tests. Returns the server and a mock delivery server.
func newSingleConnEnv(t *testing.T) (*smtpserver.Server, *mockSCDeliveryServer) {
	t.Helper()

	domainName := "single.local"

	deliverySrv := &mockSCDeliveryServer{}
	sessionSrv := &mockSCSessionServer{
		localDomains: map[string]bool{domainName: true},
	}

	socketPath := t.TempDir() + "/sm.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, deliverySrv)
	smpb.RegisterSessionServiceServer(gsrv, sessionSrv)
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	smDelivery, err := smtpserver.NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerDeliveryAgent: %v", err)
	}
	t.Cleanup(func() { _ = smDelivery.Close() })

	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:       "single.local",
		SMDelivery:     smDelivery,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
		TempDir:        t.TempDir(),
	})

	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: "127.0.0.1:0", Mode: config.ModeSmtp},
		},
		Hostname:       "single.local",
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return srv, deliverySrv
}

// mockSCDeliveryServer captures delivered messages for singleconn tests.
type mockSCDeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer
	mu       sync.Mutex
	messages int
}

func (s *mockSCDeliveryServer) Deliver(stream grpc.ClientStreamingServer[pb.DeliverRequest, pb.DeliverResponse]) error {
	var body bytes.Buffer
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if p, ok := req.Payload.(*pb.DeliverRequest_Data); ok {
			body.Write(p.Data)
		}
	}
	s.mu.Lock()
	s.messages++
	s.mu.Unlock()
	return stream.SendAndClose(&pb.DeliverResponse{
		Result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
	})
}

func (s *mockSCDeliveryServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.messages
}

// mockSCSessionServer validates recipients for singleconn tests.
type mockSCSessionServer struct {
	smpb.UnimplementedSessionServiceServer
	localDomains map[string]bool
}

func (s *mockSCSessionServer) ValidateRecipient(_ context.Context, req *smpb.ValidateRecipientRequest) (*smpb.ValidateRecipientResponse, error) {
	addr := req.Address
	domain := ""
	if idx := strings.LastIndex(addr, "@"); idx >= 0 {
		domain = strings.ToLower(addr[idx+1:])
	}
	if !s.localDomains[domain] {
		return &smpb.ValidateRecipientResponse{DomainIsLocal: false}, nil
	}
	return &smpb.ValidateRecipientResponse{
		DomainIsLocal: true,
		UserExists:    true,
	}, nil
}

// TestRunSingleConn_BasicDelivery verifies that RunSingleConn handles a
// complete SMTP DATA transaction over a net.Pipe connection and delivers mail.
func TestRunSingleConn_BasicDelivery(t *testing.T) {
	t.Parallel()

	srv, deliverySrv := newSingleConnEnv(t)

	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.RunSingleConn(serverConn, config.ModeSmtp, nil); err != nil {
			if !strings.Contains(err.Error(), "closed") {
				t.Errorf("RunSingleConn: unexpected error: %v", err)
			}
		}
	}()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "carol@single.local", "Test via RunSingleConn", "body text")
	c.Quit(t)
	_ = clientConn.Close()

	wg.Wait()

	if got := deliverySrv.count(); got != 1 {
		t.Errorf("expected 1 delivered message, got %d", got)
	}
}

// TestRunSingleConn_SessionEndsAfterQuit verifies that RunSingleConn returns
// after the client sends QUIT.
func TestRunSingleConn_SessionEndsAfterQuit(t *testing.T) {
	t.Parallel()

	srv, _ := newSingleConnEnv(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.RunSingleConn(serverConn, config.ModeSmtp, nil) //nolint:errcheck
		close(done)
	}()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}
	c.Greeting(t)
	c.Ehlo(t)
	c.Quit(t)
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after QUIT")
	}
}

// TestRunSingleConn_NoSecondConn verifies that after the first connection is
// served, RunSingleConn returns rather than waiting for another connection.
func TestRunSingleConn_NoSecondConn(t *testing.T) {
	t.Parallel()

	srv, _ := newSingleConnEnv(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.RunSingleConn(serverConn, config.ModeSmtp, nil) //nolint:errcheck
		close(done)
	}()

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after client disconnect")
	}
}
