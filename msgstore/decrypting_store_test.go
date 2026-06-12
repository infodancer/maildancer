package msgstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// mockStore is a minimal MessageStore for testing the decrypting wrapper.
type mockStore struct {
	listCalled     bool
	retrieveCalled bool
	deleteCalled   bool
	expungeCalled  bool
	statCalled     bool

	content []byte // returned by Retrieve
}

func (m *mockStore) List(_ context.Context, _ string) ([]MessageInfo, error) {
	m.listCalled = true
	return []MessageInfo{{UID: 1, Size: 42}}, nil
}

func (m *mockStore) Retrieve(_ context.Context, _ string, _ uint32) (io.ReadCloser, error) {
	m.retrieveCalled = true
	return io.NopCloser(bytes.NewReader(m.content)), nil
}

func (m *mockStore) Delete(_ context.Context, _ string, _ uint32) error {
	m.deleteCalled = true
	return nil
}

func (m *mockStore) Expunge(_ context.Context, _ string) error {
	m.expungeCalled = true
	return nil
}

func (m *mockStore) Stat(_ context.Context, _ string) (int, int64, error) {
	m.statCalled = true
	return 1, 42, nil
}

// Ensure mockStore satisfies MessageStore at compile time.
var _ MessageStore = (*mockStore)(nil)

// mockFolderStore adds FolderStore to mockStore, capturing write-through
// content so tests can assert what reached the underlying store.
type mockFolderStore struct {
	mockStore

	folderContent  []byte // returned by RetrieveFromFolder
	appended       []byte // captured by AppendToFolder
	delivered      []byte // captured by DeliverToFolder
	appendedFlags  []string
	appendedFolder string
}

var _ FolderStore = (*mockFolderStore)(nil)

func (m *mockFolderStore) CreateFolder(_ context.Context, _ string, _ string) error { return nil }
func (m *mockFolderStore) ListFolders(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockFolderStore) DeleteFolder(_ context.Context, _ string, _ string) error { return nil }
func (m *mockFolderStore) ListInFolder(_ context.Context, _ string, _ string) ([]MessageInfo, error) {
	return nil, nil
}
func (m *mockFolderStore) StatFolder(_ context.Context, _ string, _ string) (int, int64, error) {
	return 0, 0, nil
}

func (m *mockFolderStore) RetrieveFromFolder(_ context.Context, _ string, _ string, _ uint32) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.folderContent)), nil
}

func (m *mockFolderStore) DeleteInFolder(_ context.Context, _ string, _ string, _ uint32) error {
	return nil
}
func (m *mockFolderStore) ExpungeFolder(_ context.Context, _ string, _ string) error { return nil }

func (m *mockFolderStore) DeliverToFolder(_ context.Context, _ string, _ string, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	m.delivered = data
	return nil
}

func (m *mockFolderStore) RenameFolder(_ context.Context, _ string, _ string, _ string) error {
	return nil
}

func (m *mockFolderStore) AppendToFolder(_ context.Context, _ string, folder string, r io.Reader, flags []string, _ time.Time) (uint32, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	m.appended = data
	m.appendedFolder = folder
	m.appendedFlags = flags
	return 7, nil
}

func (m *mockFolderStore) SetFlagsInFolder(_ context.Context, _ string, _ string, _ uint32, _ []string) error {
	return nil
}

func (m *mockFolderStore) CopyMessage(_ context.Context, _ string, _ string, _ uint32, _ string) (uint32, error) {
	return 8, nil
}

func (m *mockFolderStore) UIDValidity(_ context.Context, _ string, _ string) (uint32, error) {
	return 1, nil
}
func (m *mockFolderStore) UIDNext(_ context.Context, _ string, _ string) (uint32, error) {
	return 9, nil
}

// genKeypair returns a fresh NaCl box keypair as plain byte slices.
func genKeypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pubArr, privArr, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pubArr[:], privArr[:]
}

func retrieveAll(t *testing.T, store MessageStore) []byte {
	t.Helper()
	rc, err := store.Retrieve(context.Background(), "alice", 1)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}

func TestDecryptingStore_PassesThroughWithoutKey(t *testing.T) {
	ctx := context.Background()
	mock := &mockStore{content: []byte("hello")}
	store := NewDecryptingStore(mock)

	if got := retrieveAll(t, store); !bytes.Equal(got, []byte("hello")) {
		t.Errorf("Retrieve without key: want raw passthrough, got %q", got)
	}
	if _, err := store.List(ctx, "alice"); err != nil || !mock.listCalled {
		t.Error("List did not delegate")
	}
	if err := store.Delete(ctx, "alice", 1); err != nil || !mock.deleteCalled {
		t.Error("Delete did not delegate")
	}
	if err := store.Expunge(ctx, "alice"); err != nil || !mock.expungeCalled {
		t.Error("Expunge did not delegate")
	}
	if _, _, err := store.Stat(ctx, "alice"); err != nil || !mock.statCalled {
		t.Error("Stat did not delegate")
	}
}

func TestDecryptingStore_DecryptsRetrieve(t *testing.T) {
	pub, priv := genKeypair(t)
	plaintext := []byte("Subject: secret\r\n\r\nciphertext at rest\r\n")
	encrypted, err := EncryptMessage(plaintext, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	store := NewDecryptingStore(&mockStore{content: encrypted})
	store.SetSessionKey(priv)

	if got := retrieveAll(t, store); !bytes.Equal(got, plaintext) {
		t.Errorf("want decrypted plaintext, got %q", got)
	}
}

func TestDecryptingStore_PlaintextFallback(t *testing.T) {
	// A message stored before encryption was enabled must come back
	// unchanged even when a session key is set.
	_, priv := genKeypair(t)
	plaintext := []byte("Subject: old\r\n\r\nplaintext at rest\r\n")

	store := NewDecryptingStore(&mockStore{content: plaintext})
	store.SetSessionKey(priv)

	if got := retrieveAll(t, store); !bytes.Equal(got, plaintext) {
		t.Errorf("want raw fallback for plaintext message, got %q", got)
	}
}

func TestDecryptingStore_WrongKeyServedRaw(t *testing.T) {
	// Content encrypted to a different key cannot be decrypted; it is
	// served raw rather than erroring (no data loss).
	pub, _ := genKeypair(t)
	_, otherPriv := genKeypair(t)
	encrypted, err := EncryptMessage([]byte("secret"), pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	store := NewDecryptingStore(&mockStore{content: encrypted})
	store.SetSessionKey(otherPriv)

	if got := retrieveAll(t, store); !bytes.Equal(got, encrypted) {
		t.Error("want raw encrypted blob when key does not match")
	}
}

func TestDecryptingStore_ClearSessionKey(t *testing.T) {
	pub, priv := genKeypair(t)
	encrypted, err := EncryptMessage([]byte("secret"), pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	store := NewDecryptingStore(&mockStore{content: encrypted})
	keyCopy := make([]byte, len(priv))
	copy(keyCopy, priv)
	store.SetSessionKey(keyCopy)

	// Caller zeroing its buffer must not affect the store's copy.
	for i := range keyCopy {
		keyCopy[i] = 0
	}
	if got := retrieveAll(t, store); bytes.Equal(got, encrypted) {
		t.Fatal("store must hold its own key copy")
	}

	store.ClearSessionKey()
	if got := retrieveAll(t, store); !bytes.Equal(got, encrypted) {
		t.Error("after ClearSessionKey, want raw passthrough")
	}
}

func TestDecryptingStore_FolderStorePreserved(t *testing.T) {
	// Wrapping a folder-capable store must keep FolderStore reachable via
	// type assertion (imapd folder support depends on this), and wrapping
	// a plain MessageStore must NOT fabricate folder support.
	withFolders := NewDecryptingStore(&mockFolderStore{})
	if _, ok := withFolders.(FolderStore); !ok {
		t.Error("wrapper over FolderStore must expose FolderStore")
	}

	withoutFolders := NewDecryptingStore(&mockStore{})
	if _, ok := withoutFolders.(FolderStore); ok {
		t.Error("wrapper over plain MessageStore must not claim FolderStore")
	}
}

func TestDecryptingStore_DecryptsRetrieveFromFolder(t *testing.T) {
	pub, priv := genKeypair(t)
	plaintext := []byte("folder message")
	encrypted, err := EncryptMessage(plaintext, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	store := NewDecryptingStore(&mockFolderStore{folderContent: encrypted})
	store.SetSessionKey(priv)

	fs := store.(FolderStore)
	rc, err := fs.RetrieveFromFolder(context.Background(), "alice", "Archive", 1)
	if err != nil {
		t.Fatalf("RetrieveFromFolder: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("want decrypted folder message, got %q", got)
	}
}

func TestDecryptingStore_EncryptsAppendToFolder(t *testing.T) {
	// IMAP APPEND (drafts, saved sent mail) through a keyed wrapper must
	// reach the underlying store as ciphertext -- otherwise client appends
	// reintroduce mixed plaintext/ciphertext mailboxes (the #53 bug class).
	_, priv := genKeypair(t)
	plaintext := []byte("Subject: draft\r\n\r\nsaved by client\r\n")

	mock := &mockFolderStore{}
	store := NewDecryptingStore(mock)
	store.SetSessionKey(priv)

	fs := store.(FolderStore)
	uid, err := fs.AppendToFolder(context.Background(), "alice", "Drafts",
		bytes.NewReader(plaintext), []string{"\\Draft"}, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if uid != 7 {
		t.Errorf("uid not delegated: got %d", uid)
	}
	if bytes.Equal(mock.appended, plaintext) {
		t.Fatal("underlying store received plaintext; append must encrypt")
	}
	decrypted, err := DecryptMessage(mock.appended, priv)
	if err != nil {
		t.Fatalf("decrypt appended blob: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("appended blob does not decrypt to original: got %q", decrypted)
	}
	if mock.appendedFolder != "Drafts" || len(mock.appendedFlags) != 1 {
		t.Error("folder/flags not delegated correctly")
	}
}

func TestDecryptingStore_EncryptsDeliverToFolder(t *testing.T) {
	_, priv := genKeypair(t)
	plaintext := []byte("delivered")

	mock := &mockFolderStore{}
	store := NewDecryptingStore(mock)
	store.SetSessionKey(priv)

	fs := store.(FolderStore)
	if err := fs.DeliverToFolder(context.Background(), "alice", "Archive", bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("DeliverToFolder: %v", err)
	}
	if bytes.Equal(mock.delivered, plaintext) {
		t.Fatal("underlying store received plaintext; deliver must encrypt")
	}
	decrypted, err := DecryptMessage(mock.delivered, priv)
	if err != nil {
		t.Fatalf("decrypt delivered blob: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("delivered blob does not decrypt to original: got %q", decrypted)
	}
}

func TestDecryptingStore_AppendWithoutKeyPassesThrough(t *testing.T) {
	plaintext := []byte("no encryption configured")
	mock := &mockFolderStore{}
	store := NewDecryptingStore(mock)

	fs := store.(FolderStore)
	if _, err := fs.AppendToFolder(context.Background(), "alice", "Drafts",
		bytes.NewReader(plaintext), nil, time.Now()); err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if !bytes.Equal(mock.appended, plaintext) {
		t.Error("append without key must pass plaintext through unchanged")
	}
}
