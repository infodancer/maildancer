package delivery

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// mockDeliveryServer implements DeliveryServiceServer for testing.
type mockDeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer

	result    pb.DeliverResult
	temporary bool
	reason    string

	// Captured from the last Deliver call.
	lastMeta *pb.DeliverMetadata
}

func (m *mockDeliveryServer) Deliver(stream pb.DeliveryService_DeliverServer) error {
	var body bytes.Buffer

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.DeliverResponse{
				Result:    m.result,
				Temporary: m.temporary,
				Reason:    m.reason,
			})
		}
		if err != nil {
			return err
		}

		switch p := req.Payload.(type) {
		case *pb.DeliverRequest_Metadata:
			m.lastMeta = p.Metadata
		case *pb.DeliverRequest_Data:
			body.Write(p.Data)
		}
	}
}

// startMockServer starts a mock DeliveryService on a random TCP port.
// Returns the client and a cleanup function.
func startMockServer(t *testing.T, mock *mockDeliveryServer) (*Client, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		t.Fatal(err)
	}

	cl := newClientFromConn(conn)
	cl.conn = conn

	cleanup := func() {
		_ = cl.Close()
		srv.Stop()
	}

	return cl, cleanup
}

func TestDeliverDSN_Success(t *testing.T) {
	mock := &mockDeliveryServer{result: pb.DeliverResult_DELIVER_RESULT_DELIVERED}
	cl, cleanup := startMockServer(t, mock)
	defer cleanup()

	body := []byte("From: MAILER-DAEMON@mail.example.com\r\nTo: user@example.com\r\n\r\nBounce message body.")

	err := cl.DeliverDSN(context.Background(), "user@example.com", body)
	if err != nil {
		t.Fatal(err)
	}

	// Verify metadata.
	if mock.lastMeta == nil {
		t.Fatal("expected metadata to be received")
	}
	if mock.lastMeta.Sender != "" {
		t.Errorf("sender should be empty (null sender), got %q", mock.lastMeta.Sender)
	}
	if mock.lastMeta.Recipient != "user@example.com" {
		t.Errorf("recipient = %q, want user@example.com", mock.lastMeta.Recipient)
	}
	if mock.lastMeta.ClientIp != "127.0.0.1" {
		t.Errorf("client_ip = %q, want 127.0.0.1", mock.lastMeta.ClientIp)
	}
	if mock.lastMeta.ClientHostname != "queue-manager" {
		t.Errorf("client_hostname = %q, want queue-manager", mock.lastMeta.ClientHostname)
	}
}

func TestDeliverDSN_Rejected(t *testing.T) {
	mock := &mockDeliveryServer{
		result:    pb.DeliverResult_DELIVER_RESULT_REJECTED,
		temporary: false,
		reason:    "mailbox full",
	}
	cl, cleanup := startMockServer(t, mock)
	defer cleanup()

	err := cl.DeliverDSN(context.Background(), "user@example.com", []byte("bounce"))
	if err == nil {
		t.Fatal("expected error for rejected delivery")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("mailbox full")) {
		t.Errorf("error should mention reason, got: %v", err)
	}
}

func TestDeliverDSN_LargeBody(t *testing.T) {
	mock := &mockDeliveryServer{result: pb.DeliverResult_DELIVER_RESULT_DELIVERED}
	cl, cleanup := startMockServer(t, mock)
	defer cleanup()

	// Body larger than chunk size (64KB) to test chunked sending.
	body := bytes.Repeat([]byte("X"), 100*1024)
	err := cl.DeliverDSN(context.Background(), "user@example.com", body)
	if err != nil {
		t.Fatal(err)
	}
}
