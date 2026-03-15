//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestStack_POP3FullStack(t *testing.T) {
	// Start mock session-manager gRPC server.
	smDir := t.TempDir()
	smSocket := smDir + "/sm.sock"
	smLn, err := net.Listen("unix", smSocket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	sessionSvc := &integrationSessionService{
		users: map[string]string{"alice@test.local": "testpass"},
	}
	mailboxSvc := &integrationMailboxService{
		messages: map[string][]*pb.MessageInfo{
			"alice@test.local": {{Uid: 1, Size: 42}},
		},
		bodies: map[uint32][]byte{
			1: []byte("From: sender@example.com\r\nTo: alice@test.local\r\nSubject: Test\r\n\r\nHello, world!\r\n"),
		},
	}

	smSrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(smSrv, sessionSvc)
	pb.RegisterMailboxServiceServer(smSrv, mailboxSvc)
	go func() { _ = smSrv.Serve(smLn) }()
	t.Cleanup(func() { smSrv.GracefulStop() })

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Build config.
	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: smSocket}
	cfg.Listeners = []config.ListenerConfig{
		{Address: addr, Mode: config.ModePop3},
	}
	cfg.Timeouts = config.TimeoutsConfig{
		Connection: "10s",
		Command:    "10s",
	}

	stack, err := pop3.NewStack(pop3.StackConfig{Config: cfg})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() {
		if err := stack.Close(); err != nil {
			t.Logf("stack.Close: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := stack.Run(ctx); err != nil {
			t.Logf("stack.Run: %v", err)
		}
	}()

	// Wait for server to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connect.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	r := bufio.NewReader(conn)

	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		t.Logf("S: %s", line)
		return line
	}
	sendLine := func(s string) {
		t.Logf("C: %s", s)
		fmt.Fprintf(conn, "%s\r\n", s)
	}

	// Greeting.
	greeting := readLine()
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// USER.
	sendLine("USER alice@test.local")
	resp := readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER failed: %s", resp)
	}

	// PASS.
	sendLine("PASS testpass")
	resp = readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS failed: %s", resp)
	}

	// STAT — expect 1 message.
	sendLine("STAT")
	resp = readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT failed: %s", resp)
	}
	// Response is "+OK <count> <octets>"
	var count, octets int
	if _, err := fmt.Sscanf(resp, "+OK %d %d", &count, &octets); err != nil {
		t.Fatalf("parse STAT response %q: %v", resp, err)
	}
	if count != 1 {
		t.Fatalf("expected 1 message, got %d", count)
	}

	// QUIT.
	sendLine("QUIT")
	readLine()
}

// integrationSessionService is a simple session service for integration tests.
type integrationSessionService struct {
	smpb.UnimplementedSessionServiceServer
	users map[string]string
}

func (s *integrationSessionService) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	pass, ok := s.users[req.Username]
	if !ok || pass != req.Password {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	return &smpb.LoginResponse{
		SessionToken: req.Username,
		Mailbox:      req.Username,
	}, nil
}

func (s *integrationSessionService) Logout(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	return &smpb.LogoutResponse{}, nil
}

// integrationMailboxService is a simple mailbox service for integration tests.
type integrationMailboxService struct {
	pb.UnimplementedMailboxServiceServer
	messages map[string][]*pb.MessageInfo
	bodies   map[uint32][]byte
}

func (s *integrationMailboxService) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	user := tokenFromCtx(ctx)
	return &pb.ListResponse{Messages: s.messages[user]}, nil
}

func (s *integrationMailboxService) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	user := tokenFromCtx(ctx)
	msgs := s.messages[user]
	var total int64
	for _, m := range msgs {
		total += m.Size
	}
	return &pb.StatResponse{Count: int32(len(msgs)), TotalBytes: total}, nil
}

func (s *integrationMailboxService) Fetch(req *pb.FetchRequest, stream grpc.ServerStreamingServer[pb.FetchResponse]) error {
	body, ok := s.bodies[req.Uid]
	if !ok {
		return status.Error(codes.NotFound, "message not found")
	}
	return stream.Send(&pb.FetchResponse{Data: body})
}

func tokenFromCtx(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		vals := md.Get("session-token")
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}
