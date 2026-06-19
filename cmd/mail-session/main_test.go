package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
)

// fakeStore is a do-nothing MessageStore used only to check whether
// maybeWrapWithDecryptingStore wrapped it.
type fakeStore struct{}

func (fakeStore) List(context.Context, string) ([]msgstore.MessageInfo, error) { return nil, nil }
func (fakeStore) Retrieve(context.Context, string, uint32) (io.ReadCloser, error) {
	return nil, nil
}
func (fakeStore) Delete(context.Context, string, uint32) error     { return nil }
func (fakeStore) Expunge(context.Context, string) error            { return nil }
func (fakeStore) Stat(context.Context, string) (int, int64, error) { return 0, 0, nil }

// pipeWith returns the read end of a pipe preloaded with b (write end closed),
// mirroring how session-manager hands a key envelope to fd 3.
func pipeWith(t *testing.T, b []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	return r
}

// isWrapped reports whether the store was wrapped in a decrypting store.
func isWrapped(s msgstore.MessageStore) bool {
	_, ok := s.(msgstore.DecryptingStore)
	return ok
}

func TestMaybeWrapWithDecryptingStore_ValidEnvelopeWraps(t *testing.T) {
	env, err := json.Marshal(keyEnvelope{Version: 1, Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	got := maybeWrapWithDecryptingStore(fakeStore{}, pipeWith(t, env))
	if !isWrapped(got) {
		t.Fatalf("valid envelope: store was not wrapped in a decrypting store")
	}
}

func TestMaybeWrapWithDecryptingStore_GarbageReturnsUnderlying(t *testing.T) {
	// The exact bytes the issue reported on the oneshot spawn: a non-JSON
	// leading 'm' that decodes to "invalid character 'm'...".
	got := maybeWrapWithDecryptingStore(fakeStore{}, pipeWith(t, []byte("mailbox-noise")))
	if isWrapped(got) {
		t.Fatalf("garbage fd 3: store should be returned unchanged, got a decrypting store")
	}
}

func TestMaybeWrapWithDecryptingStore_WrongVersionReturnsUnderlying(t *testing.T) {
	env, err := json.Marshal(keyEnvelope{Version: 2, Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	got := maybeWrapWithDecryptingStore(fakeStore{}, pipeWith(t, env))
	if isWrapped(got) {
		t.Fatalf("unsupported version: store should be returned unchanged")
	}
}

func TestMaybeWrapWithDecryptingStore_ShortKeyReturnsUnderlying(t *testing.T) {
	env, err := json.Marshal(keyEnvelope{Version: 1, Key: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	got := maybeWrapWithDecryptingStore(fakeStore{}, pipeWith(t, env))
	if isWrapped(got) {
		t.Fatalf("short key: store should be returned unchanged")
	}
}

func TestMaybeWrapWithDecryptingStore_EmptyFDReturnsUnderlying(t *testing.T) {
	// Empty pipe (EOF on first read) is the "fd 3 present but no envelope" case.
	got := maybeWrapWithDecryptingStore(fakeStore{}, pipeWith(t, nil))
	if isWrapped(got) {
		t.Fatalf("empty fd 3: store should be returned unchanged")
	}
}
