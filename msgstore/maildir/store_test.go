package maildir

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-maildir"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

func TestMaildirStore_Deliver(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	_, err := store.List(ctx, "nonexistent@example.com")
	if err != errors.ErrMailboxNotFound {
		t.Fatalf("expected ErrMailboxNotFound, got %v", err)
	}
}

func TestMaildirStore_Retrieve(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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
	store := NewStore(basePath, "", "")
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

func TestMaildirStore_DeliverSubaddress(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Deliver to a subaddressed recipient
	envelope := msgstore.Envelope{
		From:           "sender@example.com",
		Recipients:     []string{"user+folder@example.com"},
		ReceivedTime:   time.Now(),
		ClientHostname: "test",
	}
	message := strings.NewReader("Subject: Subaddress Test\r\n\r\nTest body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Message should be in the base user's mailbox (user@example.com), not user+folder@example.com
	messages, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message in user@example.com mailbox, got %d", len(messages))
	}

	// Verify that user+folder@example.com does NOT have its own separate mailbox
	_, err = store.List(ctx, "user+folder@example.com")
	if err == nil {
		t.Error("expected error listing user+folder@example.com mailbox (should not exist separately)")
	}
}

func TestMaildirStore_DeliverSubaddressWithTemplate(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "Maildir", "{domain}/users/{localpart}")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:           "sender@example.com",
		Recipients:     []string{"testuser+archive@example.com"},
		ReceivedTime:   time.Now(),
		ClientHostname: "test",
	}
	message := strings.NewReader("Subject: Template Subaddress\r\n\r\nTest body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Should be delivered to testuser@example.com's mailbox
	messages, err := store.List(ctx, "testuser@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	// Verify the path uses the base user, not the +tag
	expectedPath := basePath + "/example.com/users/testuser/Maildir/new"
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected path %s to exist", expectedPath)
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

func TestMaildirStore_PathTraversal(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Attempt path traversal attacks (using forward slashes - Unix style)
	traversalAttempts := []string{
		"../etc/passwd",
		"user/../../../etc/passwd",
		"./../../etc/passwd",
	}

	for _, mailbox := range traversalAttempts {
		envelope := msgstore.Envelope{
			From:       "sender@example.com",
			Recipients: []string{mailbox},
		}
		message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

		err := store.Deliver(ctx, envelope, message)
		if err != errors.ErrPathTraversal {
			t.Errorf("expected ErrPathTraversal for mailbox %q, got %v", mailbox, err)
		}
	}
}

func TestMaildirStore_MaildirSubdir(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "Maildir", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"testuser"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Verify message was delivered to basePath/testuser/Maildir/
	messages, err := store.List(ctx, "testuser")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestSplitEmail(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		wantLocalpart  string
		wantDomain     string
	}{
		{
			name:          "standard email",
			email:         "user@example.com",
			wantLocalpart: "user",
			wantDomain:    "example.com",
		},
		{
			name:          "no domain",
			email:         "localuser",
			wantLocalpart: "localuser",
			wantDomain:    "",
		},
		{
			name:          "multiple at signs",
			email:         "user@sub@example.com",
			wantLocalpart: "user@sub",
			wantDomain:    "example.com",
		},
		{
			name:          "empty string",
			email:         "",
			wantLocalpart: "",
			wantDomain:    "",
		},
		{
			name:          "just at sign",
			email:         "@",
			wantLocalpart: "",
			wantDomain:    "",
		},
		{
			name:          "subdomain",
			email:         "user@mail.example.com",
			wantLocalpart: "user",
			wantDomain:    "mail.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localpart, domain := splitEmail(tt.email)
			if localpart != tt.wantLocalpart {
				t.Errorf("splitEmail(%q) localpart = %q, want %q", tt.email, localpart, tt.wantLocalpart)
			}
			if domain != tt.wantDomain {
				t.Errorf("splitEmail(%q) domain = %q, want %q", tt.email, domain, tt.wantDomain)
			}
		})
	}
}

func TestMaildirStore_ExpandMailbox(t *testing.T) {
	tests := []struct {
		name         string
		pathTemplate string
		mailbox      string
		want         string
	}{
		{
			name:         "no template",
			pathTemplate: "",
			mailbox:      "user@example.com",
			want:         "user@example.com",
		},
		{
			name:         "domain and localpart template",
			pathTemplate: "{domain}/users/{localpart}",
			mailbox:      "user@example.com",
			want:         "example.com/users/user",
		},
		{
			name:         "email template",
			pathTemplate: "mailboxes/{email}",
			mailbox:      "user@example.com",
			want:         "mailboxes/user@example.com",
		},
		{
			name:         "domain only template",
			pathTemplate: "{domain}",
			mailbox:      "user@example.com",
			want:         "example.com",
		},
		{
			name:         "localpart only template",
			pathTemplate: "users/{localpart}",
			mailbox:      "user@example.com",
			want:         "users/user",
		},
		{
			name:         "no domain in email",
			pathTemplate: "{domain}/users/{localpart}",
			mailbox:      "localuser",
			want:         "/users/localuser",
		},
		{
			name:         "all variables",
			pathTemplate: "{domain}/{localpart}/{email}",
			mailbox:      "user@example.com",
			want:         "example.com/user/user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore("/tmp", "", tt.pathTemplate)
			got := store.expandMailbox(tt.mailbox)
			if got != tt.want {
				t.Errorf("expandMailbox(%q) = %q, want %q", tt.mailbox, got, tt.want)
			}
		})
	}
}

func TestMaildirStore_PathTemplate(t *testing.T) {
	basePath := t.TempDir()
	// Template: example.com/users/user/Maildir/
	store := NewStore(basePath, "Maildir", "{domain}/users/{localpart}")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"testuser@example.com"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Verify message was delivered
	messages, err := store.List(ctx, "testuser@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	// Verify the path structure exists
	expectedPath := basePath + "/example.com/users/testuser/Maildir/new"
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected path %s to exist", expectedPath)
	}
}

func TestMaildirStore_PathTemplateMultipleDomains(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "Maildir", "{domain}/users/{localpart}")
	ctx := context.Background()

	// Deliver to users in different domains
	users := []string{"user1@example.com", "user2@other.org"}
	for _, user := range users {
		envelope := msgstore.Envelope{
			From:       "sender@example.com",
			Recipients: []string{user},
		}
		message := strings.NewReader("Subject: Test\r\n\r\nTest message body")
		if err := store.Deliver(ctx, envelope, message); err != nil {
			t.Fatalf("Deliver to %s failed: %v", user, err)
		}
	}

	// Verify each user has their message
	for _, user := range users {
		messages, err := store.List(ctx, user)
		if err != nil {
			t.Fatalf("List failed for %s: %v", user, err)
		}
		if len(messages) != 1 {
			t.Fatalf("expected 1 message for %s, got %d", user, len(messages))
		}
	}

	// Verify the directory structure
	expectedPaths := []string{
		basePath + "/example.com/users/user1/Maildir",
		basePath + "/other.org/users/user2/Maildir",
	}
	for _, path := range expectedPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected path %s to exist", path)
		}
	}
}
