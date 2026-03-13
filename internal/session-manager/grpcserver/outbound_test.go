package grpcserver

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestOutboundEnqueue(t *testing.T) {
	queueDir := t.TempDir()

	cfg := queue.Config{
		Dir:        queueDir,
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
	}

	// Start a gRPC server with OutboundService.
	gsrv := grpc.NewServer()
	pb.RegisterOutboundServiceServer(gsrv, &outboundServer{
		queueCfg:    cfg,
		domainsPath: t.TempDir(), // no DKIM keys configured
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(gsrv.Stop)

	// Connect client.
	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := pb.NewOutboundServiceClient(conn)

	// Send metadata + body.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Enqueue(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Send metadata.
	if err := stream.Send(&pb.EnqueueRequest{
		Payload: &pb.EnqueueRequest_Metadata{
			Metadata: &pb.EnqueueMetadata{
				Sender:     "alice@example.com",
				Recipients: []string{"bob@gmail.com", "carol@yahoo.com"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Send body in two chunks.
	bodyPart1 := "From: alice@example.com\r\nTo: bob@gmail.com\r\nSubject: test\r\n"
	bodyPart2 := "\r\nHello, world!\r\n"

	if err := stream.Send(&pb.EnqueueRequest{
		Payload: &pb.EnqueueRequest_Data{Data: []byte(bodyPart1)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.EnqueueRequest{
		Payload: &pb.EnqueueRequest_Data{Data: []byte(bodyPart2)},
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}

	if resp.MessageId == "" {
		t.Fatal("empty message_id in response")
	}

	// Verify body file exists.
	msgDir := filepath.Join(queueDir, "msg", "com", "example")
	bodies := readTestDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body file, got %d: %v", len(bodies), bodies)
	}

	bodyContent, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bodyContent), "Message-ID:") {
		t.Error("body missing Message-ID header")
	}
	if !strings.Contains(string(bodyContent), "Hello, world!") {
		t.Error("body missing expected content")
	}

	// Verify envelope files exist for both recipients.
	for _, rcpt := range []struct{ local, tld, sld string }{
		{"bob", "com", "gmail"},
		{"carol", "com", "yahoo"},
	} {
		envDir := filepath.Join(queueDir, "env", rcpt.tld, rcpt.sld)
		envFiles := readTestDir(t, envDir)
		if len(envFiles) == 0 {
			t.Errorf("no envelope files for %s@%s.%s", rcpt.local, rcpt.sld, rcpt.tld)
			continue
		}

		// Parse and verify envelope content.
		envContent, err := os.ReadFile(filepath.Join(envDir, envFiles[0]))
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Sender    string `json:"sender"`
			Recipient string `json:"recipient"`
			MsgID     string `json:"msgid"`
			Origin    string `json:"origin"`
		}
		if err := json.Unmarshal(envContent, &env); err != nil {
			t.Fatal(err)
		}
		if env.Origin != "alice@example.com" {
			t.Errorf("envelope Origin: got %q, want %q", env.Origin, "alice@example.com")
		}
		if env.MsgID != resp.MessageId {
			t.Errorf("envelope MsgID %q != response MessageId %q", env.MsgID, resp.MessageId)
		}
	}
}

func TestOutboundEnqueue_MissingMetadata(t *testing.T) {
	gsrv := grpc.NewServer()
	pb.RegisterOutboundServiceServer(gsrv, &outboundServer{
		queueCfg:    queue.Config{Dir: t.TempDir(), MessageTTL: time.Hour, Hostname: "test"},
		domainsPath: t.TempDir(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := pb.NewOutboundServiceClient(conn)
	ctx := context.Background()

	// Send data without metadata first.
	stream, err := client.Enqueue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.EnqueueRequest{
		Payload: &pb.EnqueueRequest_Data{Data: []byte("body")},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.CloseAndRecv()
	if err == nil {
		t.Error("expected error when sending data without metadata")
	}
}

func readTestDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}
