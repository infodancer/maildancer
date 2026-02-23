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

	// Verify directory structure on disk
	folderPath := filepath.Join(basePath, "user@example.com", ".work")
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
	if len(folders) != 3 {
		t.Fatalf("expected 3 folders, got %d: %v", len(folders), folders)
	}

	// Check all folders present (order may vary)
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
	if len(folders) != 0 {
		t.Fatalf("expected 0 folders, got %d", len(folders))
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

	// Verify directory is removed
	folderPath := filepath.Join(basePath, "user@example.com", ".work")
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
		Recipients: []string{"testuser"},
	}
	if err := store.Deliver(ctx, envelope, strings.NewReader("Subject: Test\r\n\r\nBody")); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Create folder
	if err := store.CreateFolder(ctx, "testuser", "archive"); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	// Verify .archive is under Maildir subdir
	expectedPath := filepath.Join(basePath, "testuser", "Maildir", ".archive", "cur")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("expected path %s to exist", expectedPath)
	}

	// Deliver and verify
	msg := strings.NewReader("Subject: Subdir Folder\r\n\r\nBody")
	if err := store.DeliverToFolder(ctx, "testuser", "archive", msg); err != nil {
		t.Fatalf("DeliverToFolder failed: %v", err)
	}

	messages, err := store.ListInFolder(ctx, "testuser", "archive")
	if err != nil {
		t.Fatalf("ListInFolder failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
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
