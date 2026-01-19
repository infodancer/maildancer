package maildir

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

func TestMaildirStore_Deliver(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:           "sender@example.com",
		Recipients:     []string{"user@example.com"},
		ReceivedTime:   time.Now(),
		ClientIP:       nil,
		ClientHostname: "test",
	}

	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Verify message was delivered
	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestMaildirStore_DeliverNoRecipients(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{},
	}

	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	err := store.Deliver(ctx, envelope, message)
	if err != errors.ErrNoRecipients {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestMaildirStore_List(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	// Deliver two messages
	for i := 0; i < 2; i++ {
		envelope := msgstore.Envelope{
			From:       "sender@example.com",
			Recipients: []string{"user@example.com"},
		}
		message := strings.NewReader("Subject: Test\r\n\r\nTest message body")
		if err := store.Deliver(ctx, envelope, message); err != nil {
			t.Fatalf("Deliver failed: %v", err)
		}
	}

	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
}

func TestMaildirStore_ListNonexistent(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	_, err := store.List(ctx, "nonexistent@example.com")
	if err != errors.ErrMailboxNotFound {
		t.Fatalf("expected ErrMailboxNotFound, got %v", err)
	}
}

func TestMaildirStore_Retrieve(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	messageContent := "Subject: Test\r\n\r\nTest message body"
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	message := strings.NewReader(messageContent)

	if err := store.Deliver(ctx, envelope, message); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) == 0 {
		t.Fatal("no messages found")
	}

	reader, err := store.Retrieve(ctx, "user@example.com", messages[0].UID)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(data) != messageContent {
		t.Fatalf("message content mismatch: got %q, want %q", string(data), messageContent)
	}
}

func TestMaildirStore_Delete(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	if err := store.Deliver(ctx, envelope, message); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	// Delete the message
	if err := store.Delete(ctx, "user@example.com", messages[0].UID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Message should no longer appear in list
	messages, err = store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 0 {
		t.Fatalf("expected 0 messages after delete, got %d", len(messages))
	}
}

func TestMaildirStore_Expunge(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	if err := store.Deliver(ctx, envelope, message); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	uid := messages[0].UID

	// Delete and expunge
	if err := store.Delete(ctx, "user@example.com", uid); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if err := store.Expunge(ctx, "user@example.com"); err != nil {
		t.Fatalf("Expunge failed: %v", err)
	}

	// Retrieve should fail after expunge
	_, err = store.Retrieve(ctx, "user@example.com", uid)
	if err == nil {
		t.Fatal("expected error after expunge, got nil")
	}
}

func TestMaildirStore_Stat(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	// Deliver messages
	for i := 0; i < 3; i++ {
		envelope := msgstore.Envelope{
			From:       "sender@example.com",
			Recipients: []string{"user@example.com"},
		}
		message := strings.NewReader("Subject: Test\r\n\r\nTest message body")
		if err := store.Deliver(ctx, envelope, message); err != nil {
			t.Fatalf("Deliver failed: %v", err)
		}
	}

	count, totalBytes, err := store.Stat(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 messages, got %d", count)
	}
	if totalBytes == 0 {
		t.Fatal("expected non-zero total bytes")
	}
}

func TestMaildirStore_MultipleRecipients(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath)
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user1@example.com", "user2@example.com"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	if err := store.Deliver(ctx, envelope, message); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Both users should have the message
	for _, user := range envelope.Recipients {
		messages, err := store.List(ctx, user)
		if err != nil {
			t.Fatalf("List failed for %s: %v", user, err)
		}
		if len(messages) != 1 {
			t.Fatalf("expected 1 message for %s, got %d", user, len(messages))
		}
	}
}

func TestMaildir_Create(t *testing.T) {
	basePath := t.TempDir()
	md := New(basePath + "/testmaildir")

	if md.Exists() {
		t.Fatal("maildir should not exist before Create")
	}

	if err := md.Create(); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !md.Exists() {
		t.Fatal("maildir should exist after Create")
	}
}

func TestMaildir_Deliver(t *testing.T) {
	basePath := t.TempDir()
	md := New(basePath + "/testmaildir")

	if err := md.Create(); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	message := strings.NewReader("Subject: Test\r\n\r\nTest body")
	filename, err := md.Deliver(message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}
	if filename == "" {
		t.Fatal("expected non-empty filename")
	}

	// Verify file exists in new/
	files, err := md.ListNew()
	if err != nil {
		t.Fatalf("ListNew failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file in new/, got %d", len(files))
	}
	if files[0] != filename {
		t.Fatalf("filename mismatch: got %s, want %s", files[0], filename)
	}
}

func TestGenerateFilename(t *testing.T) {
	filename1 := generateFilename()
	filename2 := generateFilename()

	if filename1 == "" {
		t.Fatal("expected non-empty filename")
	}
	if filename1 == filename2 {
		t.Fatal("expected unique filenames")
	}
}

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost", "localhost"},
		{"host/name", "host_name"},
		{"host:name", "host_name"},
		{"host/name:test", "host_name_test"},
	}

	for _, tt := range tests {
		result := sanitizeHostname(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		filename string
		expected []string
	}{
		{"1234567890.P123.hostname", nil},
		{"1234567890.P123.hostname:2,S", []string{"\\Seen"}},
		{"1234567890.P123.hostname:2,SR", []string{"\\Seen", "\\Answered"}},
		{"1234567890.P123.hostname:2,SRTDF", []string{"\\Seen", "\\Answered", "\\Deleted", "\\Draft", "\\Flagged"}},
	}

	for _, tt := range tests {
		result := parseFlags(tt.filename)
		if len(result) != len(tt.expected) {
			t.Errorf("parseFlags(%q) = %v, want %v", tt.filename, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("parseFlags(%q) = %v, want %v", tt.filename, result, tt.expected)
				break
			}
		}
	}
}
