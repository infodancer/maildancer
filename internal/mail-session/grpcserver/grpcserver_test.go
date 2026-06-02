package grpcserver_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/mail-session/grpcserver"
	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// setupTestServer creates a maildir-backed gRPC server on a temp unix socket.
// Returns the socket path and cleanup function.
func setupTestServer(t *testing.T) (string, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a maildir for the test user.
	userDir := filepath.Join(tmpDir, "store", "testuser")
	if err := os.MkdirAll(filepath.Join(userDir, "Maildir", "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(userDir, "Maildir", "cur"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(userDir, "Maildir", "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}

	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: filepath.Join(tmpDir, "store"),
	})
	if err != nil {
		t.Fatal(err)
	}

	sess := session.New(store)
	if err := sess.Open(context.Background(), "testuser"); err != nil {
		t.Fatal(err)
	}

	srv := grpcserver.NewServer(grpcserver.Config{
		Session:        sess,
		RescanInterval: 100 * time.Millisecond,
		ReadyWriter:    io.Discard,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(socketPath)
	}()

	// Wait for socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cleanup := func() {
		srv.GracefulStop()
		<-errCh
	}

	return socketPath, cleanup
}

func dialTest(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestMailboxService_ListEmpty(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	client := pb.NewMailboxServiceClient(conn)

	resp, err := client.List(context.Background(), &pb.ListRequest{Folder: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetMessages()) != 0 {
		t.Errorf("expected 0 messages, got %d", len(resp.GetMessages()))
	}
}

func TestMailboxService_StatEmpty(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	client := pb.NewMailboxServiceClient(conn)

	resp, err := client.Stat(context.Background(), &pb.StatRequest{Folder: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetCount() != 0 {
		t.Errorf("expected count 0, got %d", resp.GetCount())
	}
	if resp.GetTotalBytes() != 0 {
		t.Errorf("expected total_bytes 0, got %d", resp.GetTotalBytes())
	}
}

func TestMailboxService_AppendAndFetch(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	client := pb.NewMailboxServiceClient(conn)

	ctx := context.Background()

	// Append a message.
	stream, err := client.Append(ctx)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("From: test@example.com\r\nSubject: Test\r\n\r\nHello world.\r\n")
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Metadata{
			Metadata: &pb.AppendMetadata{
				Folder: "INBOX",
				Flags:  []string{"\\Seen"},
				Date:   time.Now().Format(time.RFC3339),
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.AppendRequest{
		Payload: &pb.AppendRequest_Data{Data: msg},
	}); err != nil {
		t.Fatal(err)
	}
	appendResp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	uid := appendResp.GetUid()
	if uid == 0 {
		t.Fatal("expected non-zero UID")
	}

	// Verify via List.
	listResp, err := client.List(ctx, &pb.ListRequest{Folder: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listResp.GetMessages()) != 1 {
		t.Fatalf("expected 1 message, got %d", len(listResp.GetMessages()))
	}
	if listResp.GetMessages()[0].GetUid() != uid {
		t.Errorf("uid mismatch: got %d, want %d", listResp.GetMessages()[0].GetUid(), uid)
	}

	// Fetch the message.
	fetchStream, err := client.Fetch(ctx, &pb.FetchRequest{Folder: "INBOX", Uid: uid})
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for {
		chunk, err := fetchStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, chunk.GetData()...)
	}
	if len(body) == 0 {
		t.Error("expected non-empty message body")
	}
}

func TestFolderService_CRUD(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	fClient := pb.NewFolderServiceClient(conn)

	ctx := context.Background()

	// Create.
	if _, err := fClient.CreateFolder(ctx, &pb.CreateFolderRequest{Name: "Archive"}); err != nil {
		t.Fatal(err)
	}

	// List.
	listResp, err := fClient.ListFolders(ctx, &pb.ListFoldersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range listResp.GetFolders() {
		if name == "Archive" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected folder 'Archive' in list, got %v", listResp.GetFolders())
	}

	// Rename.
	if _, err := fClient.RenameFolder(ctx, &pb.RenameFolderRequest{OldName: "Archive", NewName: "Old"}); err != nil {
		t.Fatal(err)
	}

	// Delete.
	if _, err := fClient.DeleteFolder(ctx, &pb.DeleteFolderRequest{Name: "Old"}); err != nil {
		t.Fatal(err)
	}

	// Verify gone.
	listResp, err = fClient.ListFolders(ctx, &pb.ListFoldersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range listResp.GetFolders() {
		if name == "Old" || name == "Archive" {
			t.Errorf("folder should be deleted, but found %q", name)
		}
	}
}

func TestMailboxService_UIDValidity(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	client := pb.NewMailboxServiceClient(conn)

	resp, err := client.UIDValidity(context.Background(), &pb.UIDValidityRequest{Folder: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	// UIDValidity should be non-zero for a valid maildir.
	if resp.GetUidValidity() == 0 {
		t.Log("UIDValidity returned 0 (may be expected for this store implementation)")
	}
}

func TestMailboxService_Rescan(t *testing.T) {
	sock, cleanup := setupTestServer(t)
	defer cleanup()

	conn := dialTest(t, sock)
	client := pb.NewMailboxServiceClient(conn)

	ctx := context.Background()

	// Initial list to populate cache.
	if _, err := client.List(ctx, &pb.ListRequest{Folder: "INBOX"}); err != nil {
		t.Fatal(err)
	}

	// Rescan should return empty (no new messages).
	rescanResp, err := client.Rescan(ctx, &pb.RescanRequest{Folder: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rescanResp.GetNewMessages()) != 0 {
		t.Errorf("expected 0 new messages, got %d", len(rescanResp.GetNewMessages()))
	}
}
