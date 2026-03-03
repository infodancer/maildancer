package msgstore

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// mockStore is a minimal MessageStore for testing PassthroughDecryptingStore.
type mockStore struct {
	listCalled     bool
	retrieveCalled bool
	deleteCalled   bool
	expungeCalled  bool
	statCalled     bool
}

func (m *mockStore) List(_ context.Context, _ string) ([]MessageInfo, error) {
	m.listCalled = true
	return []MessageInfo{{UID: "1", Size: 42}}, nil
}

func (m *mockStore) Retrieve(_ context.Context, _ string, _ string) (io.ReadCloser, error) {
	m.retrieveCalled = true
	return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
}

func (m *mockStore) Delete(_ context.Context, _ string, _ string) error {
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

func TestPassthroughDecryptingStore_PassesThrough(t *testing.T) {
	ctx := context.Background()
	mock := &mockStore{}
	store := NewPassthroughDecryptingStore(mock)

	if _, err := store.List(ctx, "inbox"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !mock.listCalled {
		t.Error("List not delegated to underlying store")
	}

	if _, err := store.Retrieve(ctx, "inbox", "1"); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if !mock.retrieveCalled {
		t.Error("Retrieve not delegated to underlying store")
	}

	if err := store.Delete(ctx, "inbox", "1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !mock.deleteCalled {
		t.Error("Delete not delegated to underlying store")
	}

	if err := store.Expunge(ctx, "inbox"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if !mock.expungeCalled {
		t.Error("Expunge not delegated to underlying store")
	}

	if _, _, err := store.Stat(ctx, "inbox"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !mock.statCalled {
		t.Error("Stat not delegated to underlying store")
	}
}

func TestPassthroughDecryptingStore_SetAndClearSessionKey(t *testing.T) {
	store := NewPassthroughDecryptingStore(&mockStore{})

	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	store.SetSessionKey(key)

	if len(store.sessionKey) != len(key) {
		t.Fatalf("expected sessionKey length %d, got %d", len(key), len(store.sessionKey))
	}
	for i, b := range key {
		if store.sessionKey[i] != b {
			t.Errorf("sessionKey[%d]: got %d, want %d", i, store.sessionKey[i], b)
		}
	}

	// Verify the stored key is a copy, not the original slice.
	key[0] = 0xFF
	if store.sessionKey[0] == 0xFF {
		t.Error("SetSessionKey should copy the key, not store a reference")
	}

	store.ClearSessionKey()

	if store.sessionKey != nil {
		t.Error("sessionKey should be nil after ClearSessionKey")
	}
}

func TestPassthroughDecryptingStore_ClearSessionKey_ZeroesBytes(t *testing.T) {
	store := NewPassthroughDecryptingStore(&mockStore{})

	key := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	store.SetSessionKey(key)

	// Capture a reference to the internal slice before clearing.
	internal := store.sessionKey

	store.ClearSessionKey()

	// The bytes that were in the slice should be zeroed.
	for i, b := range internal {
		if b != 0 {
			t.Errorf("byte %d not zeroed after ClearSessionKey: got %d", i, b)
		}
	}
}

func TestPassthroughDecryptingStore_SatisfiesDecryptingStore(_ *testing.T) {
	// Compile-time check; if this compiles, the interface is satisfied.
	var _ DecryptingStore = NewPassthroughDecryptingStore(&mockStore{})
}

// Ensure mockStore satisfies MessageStore at compile time.
var _ MessageStore = (*mockStore)(nil)

