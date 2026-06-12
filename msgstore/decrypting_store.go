package msgstore

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"time"

	"golang.org/x/crypto/curve25519"
)

// decryptingStore implements DecryptingStore with real decryption: when a
// session key is set, retrieved messages are decrypted with DecryptMessage.
// Content that does not decrypt (plaintext stored before encryption was
// enabled, or a blob for a different key) is served raw -- never an error,
// never data loss. Without a session key every operation is a passthrough.
//
// The wrapper is created in mail-session after the fd 3 key envelope is
// read; the key arrives from session-manager, which captured it from the
// auth session at login time.
type decryptingStore struct {
	underlying MessageStore
	sessionKey []byte
	publicKey  []byte // derived from sessionKey; used to encrypt write-through
}

// decryptingFolderStore extends decryptingStore with FolderStore coverage so
// that wrapping a folder-capable store (maildir) keeps IMAP folder support
// reachable by type assertion. Folder retrieval decrypts; folder writes
// (AppendToFolder for IMAP APPEND, DeliverToFolder) encrypt with the derived
// public key so client appends cannot reintroduce plaintext into an
// encrypted mailbox.
type decryptingFolderStore struct {
	*decryptingStore
	folders FolderStore
}

// Compile-time interface checks.
var (
	_ DecryptingStore = (*decryptingStore)(nil)
	_ DecryptingStore = (*decryptingFolderStore)(nil)
	_ FolderStore     = (*decryptingFolderStore)(nil)
)

// NewDecryptingStore wraps a MessageStore with transparent decryption.
// If the underlying store also implements FolderStore, the returned store
// does too -- folder retrieval decrypts and folder writes encrypt.
func NewDecryptingStore(underlying MessageStore) DecryptingStore {
	base := &decryptingStore{underlying: underlying}
	if fs, ok := underlying.(FolderStore); ok {
		return &decryptingFolderStore{decryptingStore: base, folders: fs}
	}
	return base
}

// SetSessionKey stores the user's private key for this session and derives
// the matching public key for write-through encryption. The key is copied;
// the caller may zero its buffer after this call.
func (s *decryptingStore) SetSessionKey(key []byte) {
	cp := make([]byte, len(key))
	copy(cp, key)
	s.sessionKey = cp

	s.publicKey = nil
	if len(cp) == PublicKeySize {
		pub, err := curve25519.X25519(cp, curve25519.Basepoint)
		if err != nil {
			// Cannot derive a public key from this scalar; retrieval still
			// decrypts, but write-through encryption is unavailable.
			slog.Warn("deriving public key from session key failed; appends will not be encrypted",
				slog.String("error", err.Error()))
		} else {
			s.publicKey = pub
		}
	}
}

// ClearSessionKey zeroes the stored key bytes and releases them.
func (s *decryptingStore) ClearSessionKey() {
	for i := range s.sessionKey {
		s.sessionKey[i] = 0
	}
	s.sessionKey = nil
	s.publicKey = nil
}

// decryptOrRaw reads all content and attempts decryption with the session
// key. Plaintext messages and undecryptable blobs come back unchanged.
func (s *decryptingStore) decryptOrRaw(rc io.ReadCloser) (io.ReadCloser, error) {
	data, err := io.ReadAll(rc)
	closeErr := rc.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	if plain, err := DecryptMessage(data, s.sessionKey); err == nil {
		data = plain
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// encryptForWrite encrypts the message with the derived public key. With no
// key (or no derivable public key) the reader passes through unchanged.
func (s *decryptingStore) encryptForWrite(r io.Reader) (io.Reader, error) {
	if s.publicKey == nil {
		return r, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	encrypted, err := EncryptMessage(data, s.publicKey)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(encrypted), nil
}

// --- MessageStore ---

func (s *decryptingStore) List(ctx context.Context, mailbox string) ([]MessageInfo, error) {
	// Note: sizes reflect stored (possibly encrypted) bytes, not plaintext.
	return s.underlying.List(ctx, mailbox)
}

func (s *decryptingStore) Retrieve(ctx context.Context, mailbox string, uid uint32) (io.ReadCloser, error) {
	rc, err := s.underlying.Retrieve(ctx, mailbox, uid)
	if err != nil || s.sessionKey == nil {
		return rc, err
	}
	return s.decryptOrRaw(rc)
}

func (s *decryptingStore) Delete(ctx context.Context, mailbox string, uid uint32) error {
	return s.underlying.Delete(ctx, mailbox, uid)
}

func (s *decryptingStore) Expunge(ctx context.Context, mailbox string) error {
	return s.underlying.Expunge(ctx, mailbox)
}

func (s *decryptingStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	// Note: total bytes reflect stored (possibly encrypted) sizes.
	return s.underlying.Stat(ctx, mailbox)
}

// --- FolderStore (decryptingFolderStore only) ---

func (s *decryptingFolderStore) CreateFolder(ctx context.Context, mailbox, folder string) error {
	return s.folders.CreateFolder(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) ListFolders(ctx context.Context, mailbox string) ([]string, error) {
	return s.folders.ListFolders(ctx, mailbox)
}

func (s *decryptingFolderStore) DeleteFolder(ctx context.Context, mailbox, folder string) error {
	return s.folders.DeleteFolder(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) ListInFolder(ctx context.Context, mailbox, folder string) ([]MessageInfo, error) {
	return s.folders.ListInFolder(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) StatFolder(ctx context.Context, mailbox, folder string) (int, int64, error) {
	return s.folders.StatFolder(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) RetrieveFromFolder(ctx context.Context, mailbox, folder string, uid uint32) (io.ReadCloser, error) {
	rc, err := s.folders.RetrieveFromFolder(ctx, mailbox, folder, uid)
	if err != nil || s.sessionKey == nil {
		return rc, err
	}
	return s.decryptOrRaw(rc)
}

func (s *decryptingFolderStore) DeleteInFolder(ctx context.Context, mailbox, folder string, uid uint32) error {
	return s.folders.DeleteInFolder(ctx, mailbox, folder, uid)
}

func (s *decryptingFolderStore) ExpungeFolder(ctx context.Context, mailbox, folder string) error {
	return s.folders.ExpungeFolder(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) DeliverToFolder(ctx context.Context, mailbox, folder string, message io.Reader) error {
	r, err := s.encryptForWrite(message)
	if err != nil {
		return err
	}
	return s.folders.DeliverToFolder(ctx, mailbox, folder, r)
}

func (s *decryptingFolderStore) RenameFolder(ctx context.Context, mailbox, oldName, newName string) error {
	return s.folders.RenameFolder(ctx, mailbox, oldName, newName)
}

func (s *decryptingFolderStore) AppendToFolder(ctx context.Context, mailbox, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	er, err := s.encryptForWrite(r)
	if err != nil {
		return 0, err
	}
	return s.folders.AppendToFolder(ctx, mailbox, folder, er, flags, date)
}

func (s *decryptingFolderStore) SetFlagsInFolder(ctx context.Context, mailbox, folder string, uid uint32, flags []string) error {
	return s.folders.SetFlagsInFolder(ctx, mailbox, folder, uid, flags)
}

func (s *decryptingFolderStore) CopyMessage(ctx context.Context, mailbox, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	// The stored blob is copied as-is; an encrypted message stays encrypted.
	return s.folders.CopyMessage(ctx, mailbox, srcFolder, uid, destFolder)
}

func (s *decryptingFolderStore) UIDValidity(ctx context.Context, mailbox, folder string) (uint32, error) {
	return s.folders.UIDValidity(ctx, mailbox, folder)
}

func (s *decryptingFolderStore) UIDNext(ctx context.Context, mailbox, folder string) (uint32, error) {
	return s.folders.UIDNext(ctx, mailbox, folder)
}
