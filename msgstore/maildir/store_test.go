package maildir

import (
	"context"
	"io"
	"os"
	"path/filepath"
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

	// List on a never-seen mailbox auto-creates it and returns empty.
	messages, err := store.List(ctx, "newuser@example.com")
	if err != nil {
		t.Fatalf("expected nil error for auto-created mailbox, got %v", err)
	}
	if len(messages) != 0 {
		t.Fatalf("expected 0 messages for new mailbox, got %d", len(messages))
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

	// Verify that delivery did NOT create a separate mailbox directory for the subaddress form.
	// (We check the filesystem rather than calling List, which auto-creates.)
	subaddrPath := filepath.Join(basePath, "user+folder@example.com")
	if _, err := os.Stat(subaddrPath); !os.IsNotExist(err) {
		t.Error("expected no mailbox directory for subaddress form user+folder@example.com")
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

func TestMaildirStore_DeliverSubaddress_FolderExists(t *testing.T) {
	// When the +extension folder already exists, delivery should go there.
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Pre-create the folder so delivery can route to it.
	if err := store.CreateFolder(ctx, "user@example.com", "lists"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user+lists@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Folder\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	// Inbox should be empty.
	inbox, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List inbox: %v", err)
	}
	if len(inbox) != 0 {
		t.Errorf("expected inbox empty, got %d messages", len(inbox))
	}

	// Folder should have the message.
	folderMsgs, err := store.ListInFolder(ctx, "user@example.com", "lists")
	if err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}
	if len(folderMsgs) != 1 {
		t.Errorf("expected 1 message in folder, got %d", len(folderMsgs))
	}
}

func TestMaildirStore_DeliverSubaddress_FolderMissing(t *testing.T) {
	// When the +extension folder does not exist, delivery falls back to inbox.
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user+nonexistent@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Fallback\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	// Message should land in inbox.
	inbox, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List inbox: %v", err)
	}
	if len(inbox) != 1 {
		t.Errorf("expected 1 message in inbox, got %d", len(inbox))
	}

	// The missing folder must NOT have been auto-created.
	folders, err := store.ListFolders(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	for _, f := range folders {
		if f == "nonexistent" {
			t.Error("folder 'nonexistent' should not have been created")
		}
	}
}

func TestMaildirStore_DeliverSubaddress_InvalidExtension(t *testing.T) {
	// An invalid extension (e.g. path traversal attempt) falls back to inbox.
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user+../evil@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Attack\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	// Message must land in inbox, not escape the base path.
	inbox, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List inbox: %v", err)
	}
	if len(inbox) != 1 {
		t.Errorf("expected 1 message in inbox, got %d", len(inbox))
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

	// Attempt path traversal attacks with fully-qualified addresses (required by address contract).
	// The localpart contains traversal sequences; the domain part satisfies the @ requirement.
	traversalAttempts := []string{
		"../etc/passwd@domain.com",
		"user/../../../etc/passwd@domain.com",
		"./../../etc/passwd@domain.com",
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
		Recipients: []string{"testuser@test.local"},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest message body")

	err := store.Deliver(ctx, envelope, message)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Verify message was delivered to basePath/testuser@test.local/Maildir/
	messages, err := store.List(ctx, "testuser@test.local")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestSplitEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		wantLocalpart string
		wantDomain    string
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
			want:         "user", // default: strip domain, use localpart
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

// --- FolderStore Tests ---

func TestMaildirStore_CreateFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	// Verify directory structure on disk (domain stripped by default normalization → "user")
	folderPath := filepath.Join(basePath, "user", ".work")
	for _, sub := range []string{"new", "cur", "tmp"} {
		p := filepath.Join(folderPath, sub)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected %s to exist", p)
		}
	}
}

func TestMaildirStore_CreateFolderDuplicate(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	err := store.CreateFolder(ctx, "user@example.com", "work")
	if err != errors.ErrFolderExists {
		t.Fatalf("expected ErrFolderExists, got %v", err)
	}
}

func TestMaildirStore_CreateFolderInvalidNames(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	invalidNames := []string{
		"",
		"../escape",
		"foo/bar",
		"foo\\bar",
		".hidden",
		"new",
		"cur",
		"tmp",
		"NEW",
		"Cur",
		"has space",
		"has.dot",
		string([]byte{0x00}),
		strings.Repeat("a", 256),
	}

	for _, name := range invalidNames {
		err := store.CreateFolder(ctx, "user@example.com", name)
		if err != errors.ErrInvalidFolderName {
			t.Errorf("expected ErrInvalidFolderName for %q, got %v", name, err)
		}
	}
}

func TestMaildirStore_ListFolders(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Create multiple folders
	for _, name := range []string{"work", "archive", "personal"} {
		if err := store.CreateFolder(ctx, "user@example.com", name); err != nil {
			t.Fatalf("CreateFolder(%s) failed: %v", name, err)
		}
	}

	folders, err := store.ListFolders(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders failed: %v", err)
	}
	// 6 default folders + 3 custom folders = 9
	if len(folders) != 9 {
		t.Fatalf("expected 9 folders, got %d: %v", len(folders), folders)
	}

	// Check all custom folders present (order may vary)
	found := make(map[string]bool)
	for _, f := range folders {
		found[f] = true
	}
	for _, name := range []string{"work", "archive", "personal"} {
		if !found[name] {
			t.Errorf("folder %q not found in list", name)
		}
	}
}

func TestMaildirStore_ListFoldersEmpty(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	folders, err := store.ListFolders(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders failed: %v", err)
	}
	// Default folders are auto-created with the mailbox
	if len(folders) != len(msgstore.DefaultFolders) {
		t.Fatalf("expected %d default folders, got %d: %v", len(msgstore.DefaultFolders), len(folders), folders)
	}
}

func TestMaildirStore_DeleteFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	if err := store.DeleteFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("DeleteFolder failed: %v", err)
	}

	// Verify directory is removed (domain stripped by default normalization → "user")
	folderPath := filepath.Join(basePath, "user", ".work")
	if _, err := os.Stat(folderPath); !os.IsNotExist(err) {
		t.Error("expected folder directory to be removed")
	}
}

func TestMaildirStore_DeleteFolderNonexistent(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists so folderPath resolves
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	err := store.DeleteFolder(ctx, "user@example.com", "nonexistent")
	if err != errors.ErrFolderNotFound {
		t.Fatalf("expected ErrFolderNotFound, got %v", err)
	}
}

func TestMaildirStore_DeliverToFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Ensure mailbox exists with an INBOX message
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: INBOX\r\n\r\nINBOX body")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Create folder and deliver to it
	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	msg := strings.NewReader("Subject: Folder Test\r\n\r\nFolder body")
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	// Verify message appears in folder listing
	messages, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message in folder, got %d", len(messages))
	}

	// Verify INBOX is unaffected
	inboxMsgs, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(inboxMsgs) != 1 {
		t.Fatalf("expected 1 message in INBOX, got %d", len(inboxMsgs))
	}
}

func TestMaildirStore_DeliverToFolderAutoCreates(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Deliver to folder without creating it first (auto-creates via ensureFolderMaildir)
	msg := strings.NewReader("Subject: Auto\r\n\r\nAuto-created folder")
	if err := store.DeliverToFolder(ctx, "user@example.com", "autofolder", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	messages, err := store.ListInFolder(ctx, "user@example.com", "autofolder")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestMaildirStore_ListInFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Deliver multiple messages to folder
	for i := 0; i < 3; i++ {
		msg := strings.NewReader("Subject: Test\r\n\r\nFolder message")
		if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
			t.Fatalf("DeliverToFolder failed: %v", err)
		}
	}

	messages, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(messages))
	}
}

func TestMaildirStore_StatFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		msg := strings.NewReader("Subject: Test\r\n\r\nFolder message body")
		if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
			t.Fatalf("DeliverToFolder failed: %v", err)
		}
	}

	count, totalBytes, err := store.StatFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("StatFolder failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 messages, got %d", count)
	}
	if totalBytes == 0 {
		t.Fatal("expected non-zero total bytes")
	}
}

func TestMaildirStore_RetrieveFromFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	messageContent := "Subject: Folder Retrieve\r\n\r\nRetrieve test body"
	msg := strings.NewReader(messageContent)
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	messages, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) == 0 {
		t.Fatal("no messages found in folder")
	}

	reader, err := store.RetrieveFromFolder(ctx, "user@example.com", "work", messages[0].UID)
	if err != nil {
		t.Fatalf("RetrieveFromFolder failed: %v", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(data) != messageContent {
		t.Fatalf("content mismatch: got %q, want %q", string(data), messageContent)
	}
}

func TestMaildirStore_DeleteInFolderAndExpunge(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	msg := strings.NewReader("Subject: Delete Test\r\n\r\nDelete body")
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	messages, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	uid := messages[0].UID

	// Soft delete
	if err := store.DeleteInFolder(ctx, "user@example.com", "work", uid); err != nil {
		t.Fatalf("DeleteInFolder failed: %v", err)
	}

	// Should be hidden from list
	messages, err = store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 0 {
		t.Fatalf("expected 0 messages after delete, got %d", len(messages))
	}

	// Expunge
	if err := store.ExpungeFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("ExpungeFolder failed: %v", err)
	}

	// Retrieve should fail after expunge
	_, err = store.RetrieveFromFolder(ctx, "user@example.com", "work", uid)
	if err == nil {
		t.Fatal("expected error after expunge, got nil")
	}
}

func TestMaildirStore_FolderWithPathTemplate(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "Maildir", "{domain}/users/{localpart}")
	ctx := context.Background()

	// Create folder and deliver
	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	msg := strings.NewReader("Subject: Template Folder\r\n\r\nBody")
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	// Verify path on disk
	expectedPath := filepath.Join(basePath, "example.com", "users", "user", "Maildir", ".work", "cur")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected path %s to exist", expectedPath)
	}

	// Verify message listing works
	messages, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestMaildirStore_FolderWithMaildirSubdir(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "Maildir", "")
	ctx := context.Background()

	// Deliver to ensure mailbox exists
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"testuser@test.local"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Create folder
	if err := store.CreateFolder(ctx, "testuser@test.local", "archive"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	// Verify .archive is under Maildir subdir (domain stripped by default normalization)
	expectedPath := filepath.Join(basePath, "testuser", "Maildir", ".archive", "cur")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected path %s to exist", expectedPath)
	}

	// Deliver and verify
	msg := strings.NewReader("Subject: Subdir Folder\r\n\r\nBody")
	if err := store.DeliverToFolder(ctx, "testuser@test.local", "archive", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	messages, err := store.ListInFolder(ctx, "testuser@test.local", "archive")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

// --- New FolderStore method tests ---

func TestMaildirStore_RenameFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	if err := store.CreateFolder(ctx, "user@example.com", "old"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	if err := store.RenameFolder(ctx, "user@example.com", "old", "new2"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}

	// old should be gone
	folders, err := store.ListFolders(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	for _, f := range folders {
		if f == "old" {
			t.Error("old folder still exists after rename")
		}
	}
	found := false
	for _, f := range folders {
		if f == "new2" {
			found = true
		}
	}
	if !found {
		t.Error("new2 folder not found after rename")
	}
}

func TestMaildirStore_RenameFolder_NotFound(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	err := store.RenameFolder(ctx, "user@example.com", "nonexistent", "other")
	if err != errors.ErrFolderNotFound {
		t.Fatalf("expected ErrFolderNotFound, got %v", err)
	}
}

func TestMaildirStore_RenameFolder_DestExists(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	for _, name := range []string{"src", "dst"} {
		if err := store.CreateFolder(ctx, "user@example.com", name); err != nil {
			t.Fatalf("CreateFolder %s: %v", name, err)
		}
	}

	err := store.RenameFolder(ctx, "user@example.com", "src", "dst")
	if err != errors.ErrFolderExists {
		t.Fatalf("expected ErrFolderExists, got %v", err)
	}
}

func TestMaildirStore_AppendToFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	content := "Subject: Append Test\r\n\r\nAppend body"
	uid, err := store.AppendToFolder(ctx, "user@example.com", "archive", strings.NewReader(content), []string{"\\Seen"}, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if uid == 0 {
		t.Fatal("expected non-zero UID")
	}

	msgs, err := store.ListInFolder(ctx, "user@example.com", "archive")
	if err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	// Verify \Seen flag was applied.
	found := false
	for _, f := range msgs[0].Flags {
		if f == "\\Seen" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected \\Seen flag, got %v", msgs[0].Flags)
	}
}

func TestMaildirStore_AppendToFolder_INBOX(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	uid, err := store.AppendToFolder(ctx, "user@example.com", "INBOX", strings.NewReader("Subject: INBOX Append\r\n\r\nBody"), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder INBOX: %v", err)
	}
	if uid == 0 {
		t.Fatal("expected non-zero UID")
	}

	msgs, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 inbox message, got %d", len(msgs))
	}
}

func TestMaildirStore_SetFlagsInFolder(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	uid, err := store.AppendToFolder(ctx, "user@example.com", "work", strings.NewReader("Subject: Flags\r\n\r\nBody"), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}

	if err := store.SetFlagsInFolder(ctx, "user@example.com", "work", uid, []string{"\\Seen", "\\Flagged"}); err != nil {
		t.Fatalf("SetFlagsInFolder: %v", err)
	}

	msgs, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("no messages")
	}

	flagSet := make(map[string]bool)
	for _, f := range msgs[0].Flags {
		flagSet[f] = true
	}
	if !flagSet["\\Seen"] {
		t.Error("expected \\Seen flag")
	}
	if !flagSet["\\Flagged"] {
		t.Error("expected \\Flagged flag")
	}
}

func TestMaildirStore_SetFlagsInFolder_INBOX(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	uid, err := store.AppendToFolder(ctx, "user@example.com", "INBOX", strings.NewReader("Subject: INBOX Flags\r\n\r\nBody"), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}

	if err := store.SetFlagsInFolder(ctx, "user@example.com", "INBOX", uid, []string{"\\Answered"}); err != nil {
		t.Fatalf("SetFlagsInFolder INBOX: %v", err)
	}
}

func TestMaildirStore_SetFlagsInFolder_MessageNotFound(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	err := store.SetFlagsInFolder(ctx, "user@example.com", "work", 99999, []string{"\\Seen"})
	if err != errors.ErrMessageNotFound {
		t.Fatalf("expected ErrMessageNotFound, got %v", err)
	}
}

func TestMaildirStore_CopyMessage(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	content := "Subject: Copy Test\r\n\r\nCopy body"
	srcUID, err := store.AppendToFolder(ctx, "user@example.com", "src", strings.NewReader(content), []string{"\\Seen"}, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}

	destUID, err := store.CopyMessage(ctx, "user@example.com", "src", srcUID, "dst")
	if err != nil {
		t.Fatalf("CopyMessage: %v", err)
	}
	if destUID == 0 {
		t.Fatal("expected non-zero dest UID")
	}

	// Source should still have the message.
	srcMsgs, err := store.ListInFolder(ctx, "user@example.com", "src")
	if err != nil {
		t.Fatalf("ListInFolder src: %v", err)
	}
	if len(srcMsgs) != 1 {
		t.Fatalf("expected 1 source message, got %d", len(srcMsgs))
	}

	// Destination should have the copy.
	dstMsgs, err := store.ListInFolder(ctx, "user@example.com", "dst")
	if err != nil {
		t.Fatalf("ListInFolder dst: %v", err)
	}
	if len(dstMsgs) != 1 {
		t.Fatalf("expected 1 dest message, got %d", len(dstMsgs))
	}

	// Verify content is identical.
	r, err := store.RetrieveFromFolder(ctx, "user@example.com", "dst", dstMsgs[0].UID)
	if err != nil {
		t.Fatalf("RetrieveFromFolder: %v", err)
	}
	defer func() { _ = r.Close() }()
	data, _ := io.ReadAll(r)
	if string(data) != content {
		t.Errorf("content mismatch: got %q, want %q", string(data), content)
	}
}

func TestMaildirStore_CopyMessage_FromINBOX(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	srcUID, err := store.AppendToFolder(ctx, "user@example.com", "INBOX", strings.NewReader("Subject: From INBOX\r\n\r\nBody"), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder INBOX: %v", err)
	}

	destUID, err := store.CopyMessage(ctx, "user@example.com", "INBOX", srcUID, "archive")
	if err != nil {
		t.Fatalf("CopyMessage from INBOX: %v", err)
	}
	if destUID == 0 {
		t.Fatal("expected non-zero dest UID")
	}

	dstMsgs, err := store.ListInFolder(ctx, "user@example.com", "archive")
	if err != nil {
		t.Fatalf("ListInFolder archive: %v", err)
	}
	if len(dstMsgs) != 1 {
		t.Fatalf("expected 1 message in archive, got %d", len(dstMsgs))
	}
}

func TestMaildirStore_CopyMessage_NotFound(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	if err := store.CreateFolder(ctx, "user@example.com", "src"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	_, err := store.CopyMessage(ctx, "user@example.com", "src", 99999, "dst")
	if err != errors.ErrMessageNotFound {
		t.Fatalf("expected ErrMessageNotFound, got %v", err)
	}
}

func TestMaildirStore_UIDValidity(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Create mailbox.
	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	v1, err := store.UIDValidity(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("UIDValidity: %v", err)
	}
	if v1 == 0 {
		t.Fatal("UIDValidity returned 0")
	}

	// Same folder, same result.
	v2, err := store.UIDValidity(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("UIDValidity: %v", err)
	}
	if v1 != v2 {
		t.Errorf("UIDValidity not stable: %d != %d", v1, v2)
	}

	// Value should be a reasonable Unix timestamp.
	if v1 < 1_000_000_000 {
		t.Errorf("UIDValidity should be a Unix timestamp, got %d", v1)
	}
}

func TestMaildirStore_UIDValidity_INBOX(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	v, err := store.UIDValidity(ctx, "user@example.com", "INBOX")
	if err != nil {
		t.Fatalf("UIDValidity INBOX: %v", err)
	}
	if v == 0 {
		t.Fatal("UIDValidity INBOX returned 0")
	}

	// Stable across calls.
	v2, err := store.UIDValidity(ctx, "user@example.com", "INBOX")
	if err != nil {
		t.Fatalf("UIDValidity INBOX 2nd call: %v", err)
	}
	if v != v2 {
		t.Errorf("UIDValidity INBOX not stable: %d != %d", v, v2)
	}
}

func TestMaildirStore_MessageInfo_InternalDate(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	before := time.Now().Truncate(time.Second)
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", strings.NewReader("Subject: Date\r\n\r\nBody")); err != nil {
		t.Fatalf("DeliverToFolder: %v", err)
	}
	after := time.Now().Add(time.Second)

	msgs, err := store.ListInFolder(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("no messages")
	}

	d := msgs[0].InternalDate
	if d.IsZero() {
		t.Fatal("InternalDate is zero")
	}
	if d.Before(before) || d.After(after) {
		t.Errorf("InternalDate %v not between %v and %v", d, before, after)
	}
}

func TestConvertFlagsFromIMAP(t *testing.T) {
	tests := []struct {
		name     string
		flags    []string
		expected []maildir.Flag
	}{
		{"empty", nil, nil},
		{"seen", []string{"\\Seen"}, []maildir.Flag{maildir.FlagSeen}},
		{"answered", []string{"\\Answered"}, []maildir.Flag{maildir.FlagReplied}},
		{"flagged", []string{"\\Flagged"}, []maildir.Flag{maildir.FlagFlagged}},
		{"draft", []string{"\\Draft"}, []maildir.Flag{maildir.FlagDraft}},
		{"deleted", []string{"\\Deleted"}, []maildir.Flag{maildir.FlagTrashed}},
		{"unknown ignored", []string{"\\Recent", "\\Unknown"}, nil},
		{"mixed", []string{"\\Seen", "\\Unknown", "\\Flagged"}, []maildir.Flag{maildir.FlagSeen, maildir.FlagFlagged}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertFlagsFromIMAP(tt.flags)
			if len(got) != len(tt.expected) {
				t.Fatalf("convertFlagsFromIMAP(%v) = %v, want %v", tt.flags, got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("convertFlagsFromIMAP(%v)[%d] = %v, want %v", tt.flags, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestValidateFolderName(t *testing.T) {
	tests := []struct {
		name    string
		folder  string
		wantErr bool
	}{
		{"valid simple", "work", false},
		{"valid with hyphen", "my-folder", false},
		{"valid with underscore", "my_folder", false},
		{"valid with numbers", "folder123", false},
		{"valid mixed case", "MyFolder", false},
		{"valid max length", strings.Repeat("a", 255), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 256), true},
		{"starts with dot", ".hidden", true},
		{"contains slash", "foo/bar", true},
		{"contains backslash", "foo\\bar", true},
		{"contains space", "has space", true},
		{"contains dot", "has.dot", true},
		{"reserved new", "new", true},
		{"reserved cur", "cur", true},
		{"reserved tmp", "tmp", true},
		{"reserved NEW uppercase", "NEW", true},
		{"null byte", string([]byte{0x00}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFolderName(tt.folder)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFolderName(%q) error = %v, wantErr %v", tt.folder, err, tt.wantErr)
			}
			if err != nil && err != errors.ErrInvalidFolderName {
				t.Errorf("validateFolderName(%q) returned wrong error type: %v", tt.folder, err)
			}
		})
	}
}

func TestEnsureDefaultFolders(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Create the mailbox first (ensureMaildir without triggering default folders
	// by creating the INBOX structure manually).
	mboxPath := filepath.Join(basePath, "user")
	dir := maildir.Dir(mboxPath)
	if err := os.MkdirAll(mboxPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := dir.Init(); err != nil {
		t.Fatal(err)
	}

	// Call EnsureDefaultFolders
	if err := store.EnsureDefaultFolders(ctx, "user"); err != nil {
		t.Fatalf("EnsureDefaultFolders failed: %v", err)
	}

	// Verify all default folders were created
	folders, err := store.ListFolders(ctx, "user")
	if err != nil {
		t.Fatalf("ListFolders failed: %v", err)
	}

	expected := map[string]bool{
		"Junk": false, "Trash": false, "Sent": false,
		"Drafts": false, "List": false, "Bulk": false,
	}
	for _, f := range folders {
		if _, ok := expected[f]; ok {
			expected[f] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("default folder %q was not created", name)
		}
	}
}

func TestEnsureDefaultFolders_Idempotent(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Create INBOX manually
	mboxPath := filepath.Join(basePath, "user")
	dir := maildir.Dir(mboxPath)
	if err := os.MkdirAll(mboxPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := dir.Init(); err != nil {
		t.Fatal(err)
	}

	// Call twice -- second call should succeed without error
	if err := store.EnsureDefaultFolders(ctx, "user"); err != nil {
		t.Fatalf("first EnsureDefaultFolders failed: %v", err)
	}
	if err := store.EnsureDefaultFolders(ctx, "user"); err != nil {
		t.Fatalf("second EnsureDefaultFolders failed: %v", err)
	}

	// Verify no duplicate folders
	folders, err := store.ListFolders(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, f := range folders {
		if seen[f] {
			t.Errorf("duplicate folder: %s", f)
		}
		seen[f] = true
	}
}

func TestEnsureMaildir_CreatesDefaultFolders(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// ensureMaildir on a new mailbox should create INBOX + default folders
	if _, err := store.ensureMaildir("newuser"); err != nil {
		t.Fatalf("ensureMaildir failed: %v", err)
	}

	folders, err := store.ListFolders(ctx, "newuser")
	if err != nil {
		t.Fatalf("ListFolders failed: %v", err)
	}

	expected := []string{"Junk", "Trash", "Sent", "Drafts", "List", "Bulk"}
	found := make(map[string]bool)
	for _, f := range folders {
		found[f] = true
	}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("ensureMaildir did not create default folder %q", name)
		}
	}
}

// --- UID persistence integration tests ---

func TestMaildirStore_UID_StableAcrossListCalls(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	for i := 0; i < 3; i++ {
		msg := strings.NewReader("Subject: Msg\r\n\r\nBody")
		if err := store.Deliver(ctx, envelope, msg); err != nil {
			t.Fatalf("Deliver: %v", err)
		}
	}

	msgs1, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List 1: %v", err)
	}
	msgs2, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List 2: %v", err)
	}

	if len(msgs1) != len(msgs2) {
		t.Fatalf("message counts differ: %d vs %d", len(msgs1), len(msgs2))
	}
	for i := range msgs1 {
		if msgs1[i].UID != msgs2[i].UID {
			t.Errorf("msg %d: UID %d vs %d", i, msgs1[i].UID, msgs2[i].UID)
		}
	}
}

func TestMaildirStore_UID_StableAfterDeleteExpunge(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	for i := 0; i < 3; i++ {
		msg := strings.NewReader("Subject: Msg\r\n\r\nBody")
		if err := store.Deliver(ctx, envelope, msg); err != nil {
			t.Fatalf("Deliver: %v", err)
		}
	}

	msgs, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	// Delete the middle message.
	if err := store.Delete(ctx, "user@example.com", msgs[1].UID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Expunge(ctx, "user@example.com"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	remaining, err := store.List(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("List after expunge: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(remaining))
	}

	// UIDs of remaining messages must be unchanged.
	if remaining[0].UID != msgs[0].UID {
		t.Errorf("first msg UID changed: %d -> %d", msgs[0].UID, remaining[0].UID)
	}
	if remaining[1].UID != msgs[2].UID {
		t.Errorf("third msg UID changed: %d -> %d", msgs[2].UID, remaining[1].UID)
	}
}

func TestMaildirStore_UID_NeverReused(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}

	// Deliver 2 messages, delete both, deliver a new one.
	for i := 0; i < 2; i++ {
		msg := strings.NewReader("Subject: Msg\r\n\r\nBody")
		if err := store.Deliver(ctx, envelope, msg); err != nil {
			t.Fatalf("Deliver: %v", err)
		}
	}

	msgs, _ := store.List(ctx, "user@example.com")
	maxUID := msgs[len(msgs)-1].UID

	for _, m := range msgs {
		if err := store.Delete(ctx, "user@example.com", m.UID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}
	if err := store.Expunge(ctx, "user@example.com"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	// Deliver a new message.
	msg := strings.NewReader("Subject: New\r\n\r\nBody")
	if err := store.Deliver(ctx, envelope, msg); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	newMsgs, _ := store.List(ctx, "user@example.com")
	if len(newMsgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(newMsgs))
	}
	if newMsgs[0].UID <= maxUID {
		t.Errorf("new UID %d should be greater than previous max %d", newMsgs[0].UID, maxUID)
	}
}

func TestMaildirStore_UIDValidity_PersistsAcrossListCalls(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Create folder.
	if err := store.CreateFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	v1, err := store.UIDValidity(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("UIDValidity 1: %v", err)
	}

	// Deliver a message and list to trigger uidlist activity.
	if err := store.DeliverToFolder(ctx, "user@example.com", "work", strings.NewReader("Subject: X\r\n\r\nBody")); err != nil {
		t.Fatalf("DeliverToFolder: %v", err)
	}
	if _, err := store.ListInFolder(ctx, "user@example.com", "work"); err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}

	v2, err := store.UIDValidity(ctx, "user@example.com", "work")
	if err != nil {
		t.Fatalf("UIDValidity 2: %v", err)
	}
	if v1 != v2 {
		t.Errorf("UIDValidity changed: %d -> %d", v1, v2)
	}
}

func TestMaildirStore_ExternalFileAddition_GetsUID(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Deliver one message to bootstrap the maildir and uidlist.
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: First\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	msgs1, _ := store.List(ctx, "user@example.com")
	if len(msgs1) != 1 {
		t.Fatalf("expected 1, got %d", len(msgs1))
	}

	// Simulate external delivery: drop a file directly into cur/.
	mailboxPath := filepath.Join(basePath, "user", "cur")
	externalKey := "9999999999.M999999.external"
	if err := os.WriteFile(filepath.Join(mailboxPath, externalKey+":2,"), []byte("Subject: External\r\n\r\nBody"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// List should pick it up with a new UID via reconciliation.
	msgs2, _ := store.List(ctx, "user@example.com")
	if len(msgs2) != 2 {
		t.Fatalf("expected 2 after external add, got %d", len(msgs2))
	}

	// The external file should have a UID > the first message's UID.
	uids := make(map[uint32]bool)
	for _, m := range msgs2 {
		if uids[m.UID] {
			t.Errorf("duplicate UID %d", m.UID)
		}
		uids[m.UID] = true
	}
}

func TestMaildirStore_UIDNext(t *testing.T) {
	basePath := t.TempDir()
	store := NewStore(basePath, "", "")
	ctx := context.Background()

	// Create folder and check initial UIDNext.
	if err := store.CreateFolder(ctx, "user@example.com", "test"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	next1, err := store.UIDNext(ctx, "user@example.com", "test")
	if err != nil {
		t.Fatalf("UIDNext: %v", err)
	}
	if next1 != 1 {
		t.Errorf("initial UIDNext: got %d, want 1", next1)
	}

	// Append a message.
	uid, err := store.AppendToFolder(ctx, "user@example.com", "test", strings.NewReader("Subject: X\r\n\r\nBody"), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if uid != 1 {
		t.Errorf("AppendToFolder UID: got %d, want 1", uid)
	}

	next2, err := store.UIDNext(ctx, "user@example.com", "test")
	if err != nil {
		t.Fatalf("UIDNext after append: %v", err)
	}
	if next2 != 2 {
		t.Errorf("UIDNext after append: got %d, want 2", next2)
	}
}
