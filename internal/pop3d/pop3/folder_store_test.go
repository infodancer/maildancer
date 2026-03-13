package pop3

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// mockFolderStore implements both msgstore.MessageStore and msgstore.FolderStore.
// It tracks which folders exist and what messages each folder contains.
type mockFolderStore struct {
	// inbox messages
	inbox []msgstore.MessageInfo
	// per-folder messages
	folders map[string][]msgstore.MessageInfo
}

func newMockFolderStore(folders map[string][]msgstore.MessageInfo) *mockFolderStore {
	return &mockFolderStore{
		inbox: []msgstore.MessageInfo{
			{UID: 1, Size: 100},
		},
		folders: folders,
	}
}

// MessageStore interface
func (m *mockFolderStore) List(_ context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return m.inbox, nil
}

func (m *mockFolderStore) Retrieve(_ context.Context, _ string, uid uint32) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(fmt.Sprintf("Subject: %d\r\n\r\nbody\r\n", uid))), nil
}

func (m *mockFolderStore) Delete(_ context.Context, _ string, _ uint32) error { return nil }

func (m *mockFolderStore) Expunge(_ context.Context, _ string) error { return nil }

func (m *mockFolderStore) Stat(_ context.Context, _ string) (int, int64, error) {
	var total int64
	for _, msg := range m.inbox {
		total += msg.Size
	}
	return len(m.inbox), total, nil
}

// FolderStore interface
func (m *mockFolderStore) ListFolders(_ context.Context, _ string) ([]string, error) {
	names := make([]string, 0, len(m.folders))
	for name := range m.folders {
		names = append(names, name)
	}
	return names, nil
}

func (m *mockFolderStore) CreateFolder(_ context.Context, _, _ string) error { return nil }

func (m *mockFolderStore) DeleteFolder(_ context.Context, _, _ string) error { return nil }

func (m *mockFolderStore) ListInFolder(_ context.Context, _, folder string) ([]msgstore.MessageInfo, error) {
	msgs, ok := m.folders[folder]
	if !ok {
		return nil, nil
	}
	return msgs, nil
}

func (m *mockFolderStore) StatFolder(_ context.Context, _, folder string) (int, int64, error) {
	msgs := m.folders[folder]
	var total int64
	for _, msg := range msgs {
		total += msg.Size
	}
	return len(msgs), total, nil
}

func (m *mockFolderStore) RetrieveFromFolder(_ context.Context, _, folder string, uid uint32) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(fmt.Sprintf("Subject: %s/%d\r\n\r\nbody\r\n", folder, uid))), nil
}

func (m *mockFolderStore) DeleteInFolder(_ context.Context, _, _ string, _ uint32) error { return nil }

func (m *mockFolderStore) ExpungeFolder(_ context.Context, _, _ string) error { return nil }

func (m *mockFolderStore) DeliverToFolder(_ context.Context, _, _ string, _ io.Reader) error {
	return nil
}

func (m *mockFolderStore) RenameFolder(_ context.Context, _, _, _ string) error { return nil }

func (m *mockFolderStore) AppendToFolder(_ context.Context, _, _ string, _ io.Reader, _ []string, _ time.Time) (uint32, error) {
	return 0, nil
}

func (m *mockFolderStore) SetFlagsInFolder(_ context.Context, _, _ string, _ uint32, _ []string) error {
	return nil
}

func (m *mockFolderStore) CopyMessage(_ context.Context, _, _ string, _ uint32, _ string) (uint32, error) {
	return 0, nil
}

func (m *mockFolderStore) UIDValidity(_ context.Context, _, _ string) (uint32, error) {
	return 1, nil
}

func (m *mockFolderStore) UIDNext(_ context.Context, _, _ string) (uint32, error) {
	return 2, nil
}

// helper: authenticated session ready for InitializeMailbox
func newAuthenticatedSession() *Session {
	sess := NewSession("test.example.com", config.ModePop3s, nil, true)
	sess.SetAuthenticated(&auth.AuthSession{
		User: &auth.User{
			Username: "testuser",
			Mailbox:  "/var/mail/testuser",
		},
	})
	return sess
}

func TestInitializeMailbox_NoFolder(t *testing.T) {
	store := newMockFolderStore(map[string][]msgstore.MessageInfo{
		"work": {{UID: 10, Size: 50}},
	})
	sess := newAuthenticatedSession()

	if err := sess.InitializeMailbox(context.Background(), store, ""); err != nil {
		t.Fatalf("InitializeMailbox: %v", err)
	}

	// No folder specified — should use inbox (1 message)
	if got := sess.MessageCount(); got != 1 {
		t.Errorf("MessageCount() = %d, want 1 (inbox)", got)
	}
}

func TestInitializeMailbox_FolderExists(t *testing.T) {
	folderMsgs := []msgstore.MessageInfo{
		{UID: 10, Size: 50},
		{UID: 11, Size: 75},
	}
	store := newMockFolderStore(map[string][]msgstore.MessageInfo{
		"work": folderMsgs,
	})
	sess := newAuthenticatedSession()

	if err := sess.InitializeMailbox(context.Background(), store, "work"); err != nil {
		t.Fatalf("InitializeMailbox: %v", err)
	}

	// Folder exists — should see folder messages, not inbox
	if got := sess.MessageCount(); got != 2 {
		t.Errorf("MessageCount() = %d, want 2 (folder)", got)
	}
}

func TestInitializeMailbox_FolderMissing(t *testing.T) {
	store := newMockFolderStore(map[string][]msgstore.MessageInfo{
		"work": {{UID: 10, Size: 50}},
	})
	sess := newAuthenticatedSession()

	// Request a folder that does not exist — should fall back to inbox
	if err := sess.InitializeMailbox(context.Background(), store, "nosuchfolder"); err != nil {
		t.Fatalf("InitializeMailbox: %v", err)
	}

	if got := sess.MessageCount(); got != 1 {
		t.Errorf("MessageCount() = %d, want 1 (inbox fallback)", got)
	}
}

func TestInitializeMailbox_StoreNotFolderStore(t *testing.T) {
	// Use a plain MessageStore (no FolderStore support)
	store := newMockMessageStore()
	sess := newAuthenticatedSession()

	// Extension requested but store doesn't implement FolderStore — inbox fallback
	if err := sess.InitializeMailbox(context.Background(), store, "work"); err != nil {
		t.Fatalf("InitializeMailbox: %v", err)
	}

	if got := sess.MessageCount(); got != 3 {
		t.Errorf("MessageCount() = %d, want 3 (inbox, no folder support)", got)
	}
}
