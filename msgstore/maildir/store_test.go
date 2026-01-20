package maildir

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-maildir"
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

func TestConvertFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    []maildir.Flag
		expected []string
	}{
		{
			name:     "no flags",
			flags:    nil,
			expected: nil,
		},
		{
			name:     "seen flag",
			flags:    []maildir.Flag{maildir.FlagSeen},
			expected: []string{"\\Seen"},
		},
		{
			name:     "multiple flags",
			flags:    []maildir.Flag{maildir.FlagSeen, maildir.FlagReplied, maildir.FlagFlagged},
			expected: []string{"\\Seen", "\\Answered", "\\Flagged"},
		},
		{
			name:     "all flags",
			flags:    []maildir.Flag{maildir.FlagSeen, maildir.FlagReplied, maildir.FlagFlagged, maildir.FlagDraft, maildir.FlagTrashed},
			expected: []string{"\\Seen", "\\Answered", "\\Flagged", "\\Draft", "\\Deleted"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertFlags(tt.flags)
			if len(result) != len(tt.expected) {
				t.Errorf("convertFlags(%v) = %v, want %v", tt.flags, result, tt.expected)
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("convertFlags(%v) = %v, want %v", tt.flags, result, tt.expected)
					break
				}
			}
		})
	}
}
