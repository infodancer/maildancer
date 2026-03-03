package msgstore

import (
	"context"
	"io"
)

// PassthroughDecryptingStore implements DecryptingStore as a transparent
// passthrough. All MessageStore operations are delegated to the underlying
// store unchanged. SetSessionKey stores the key in memory (zeroing it on
// ClearSessionKey) but does not yet perform decryption.
//
// This implementation provides the plumbing for the fd-based key-passing
// convention between pop3d/imapd and mail-session. A real DecryptingStore
// implementation that calls DecryptMessage on retrieved bytes will replace
// or wrap this when at-rest encryption is fully wired in.
type PassthroughDecryptingStore struct {
	underlying MessageStore
	sessionKey []byte
}

// Compile-time interface check.
var _ DecryptingStore = (*PassthroughDecryptingStore)(nil)

// NewPassthroughDecryptingStore wraps underlying in a PassthroughDecryptingStore.
func NewPassthroughDecryptingStore(underlying MessageStore) *PassthroughDecryptingStore {
	return &PassthroughDecryptingStore{underlying: underlying}
}

// SetSessionKey stores the session key for future decryption use.
// The key is copied; the caller may zero its buffer after this call.
func (s *PassthroughDecryptingStore) SetSessionKey(key []byte) {
	cp := make([]byte, len(key))
	copy(cp, key)
	s.sessionKey = cp
}

// ClearSessionKey zeroes the stored key bytes and releases the slice.
func (s *PassthroughDecryptingStore) ClearSessionKey() {
	for i := range s.sessionKey {
		s.sessionKey[i] = 0
	}
	s.sessionKey = nil
}

// List delegates to the underlying store.
func (s *PassthroughDecryptingStore) List(ctx context.Context, mailbox string) ([]MessageInfo, error) {
	return s.underlying.List(ctx, mailbox)
}

// Retrieve delegates to the underlying store.
// When decryption is implemented, this method will call DecryptMessage on
// the returned content when sessionKey is non-nil.
func (s *PassthroughDecryptingStore) Retrieve(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error) {
	return s.underlying.Retrieve(ctx, mailbox, uid)
}

// Delete delegates to the underlying store.
func (s *PassthroughDecryptingStore) Delete(ctx context.Context, mailbox string, uid string) error {
	return s.underlying.Delete(ctx, mailbox, uid)
}

// Expunge delegates to the underlying store.
func (s *PassthroughDecryptingStore) Expunge(ctx context.Context, mailbox string) error {
	return s.underlying.Expunge(ctx, mailbox)
}

// Stat delegates to the underlying store.
func (s *PassthroughDecryptingStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	return s.underlying.Stat(ctx, mailbox)
}
