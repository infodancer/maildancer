// Package keyring implements the client keyring and key-encryption-key (KEK)
// seal layer described in infodancer/infodancer docs/keyring-design.md.
//
// A keyring is a *set* of keypairs (rotation and archive access require keeping
// historic private keys), held in cleartext only inside the client or inside
// mail-session after unwrap. The server stores a Sealed keyring: an opaque blob
// it cannot read, plus a set of wrap-slots describing how the KEK is unlocked.
//
//	Sealed:
//	  version, doc_version (monotonic, for compare-and-swap)
//	  kek_wrapped_blob = XChaCha20-Poly1305(keyring, KEK), AAD = version||doc_version
//	  wrap_slots[]: {slot_type, slot_id, wrapped_kek, kdf?}
//
// The set of wrap-slots is exactly what distinguishes the three trust postures:
// passphrase/device slots only -> the server cannot decrypt (backup/sync, not
// escrow); an additional escrow slot -> the server (domain) can decrypt and
// must disclose it. This package implements the passphrase slot and the escrow
// slot *format*; escrow activation (recovery-key custody, encryption_mode, the
// published escrowed flag) is deferred.
//
// Honest caveat: in maildancer's IMAP/POP path, session-manager receives the
// plaintext login password and unwraps the keyring server-side to feed the
// fd-3 hand-off, so the server still sees the password at login. The passphrase
// slot's domain-separated KDF (argon2id then HKDF with a distinct info label)
// keeps the keyring wrap-key structurally independent of the stored auth
// verifier, but the same-secret-at-login footgun is only *fully* closed by
// client-side key derivation (native SCMP clients / OPAQUE), which is out of
// scope here.
package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// Format and document versions. Both are bound into the keyring seal's AAD, so
// a change here is a hard format break, not a silent one.
const (
	formatVersion  = 1
	keyringVersion = 1
)

// Algorithm identifies the keypair primitive for an entry.
type Algorithm string

const (
	AlgorithmX25519  Algorithm = "X25519"  // NaCl box encryption keypair
	AlgorithmEd25519 Algorithm = "Ed25519" // signing keypair
)

// Purpose distinguishes encryption keys from signing keys within the keyring.
type Purpose string

const (
	PurposeEncryption Purpose = "encryption"
	PurposeSigning    Purpose = "signing"
)

// Status tracks an entry's lifecycle. Rotated and revoked keys are retained so
// mail encrypted to them stays readable; nothing is deleted from the keyring.
type Status string

const (
	StatusActive  Status = "active"
	StatusRotated Status = "rotated"
	StatusRevoked Status = "revoked"
)

// Entry is one keypair in the keyring.
type Entry struct {
	KeyID      string    `json:"key_id"` // fingerprint of the public key
	Algorithm  Algorithm `json:"algorithm"`
	Purpose    Purpose   `json:"purpose"`
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	Created    time.Time `json:"created"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until,omitempty"`
	Status     Status    `json:"status"`
}

// Keyring is the cleartext document. It exists in the clear only on the client
// or inside mail-session after the KEK unwrap.
type Keyring struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// ActiveEncryptionKey returns the current active encryption entry. The invariant
// (one active encryption entry) is maintained by RotateEncryptionKey; the first
// match is returned defensively.
func (k *Keyring) ActiveEncryptionKey() (Entry, bool) {
	for _, e := range k.Entries {
		if e.Purpose == PurposeEncryption && e.Status == StatusActive {
			return e, true
		}
	}
	return Entry{}, false
}

// RotateEncryptionKey marks every currently-active encryption entry as rotated
// and appends e as the new active encryption key. Historic private keys are
// retained so old mail stays readable. The caller seals the result to persist
// it (which bumps doc_version).
func (k *Keyring) RotateEncryptionKey(e Entry) {
	for i := range k.Entries {
		if k.Entries[i].Purpose == PurposeEncryption && k.Entries[i].Status == StatusActive {
			k.Entries[i].Status = StatusRotated
		}
	}
	k.normalizeEntry(&e)
	e.Status = StatusActive
	k.Entries = append(k.Entries, e)
}

// normalizeEntry fills in derived/default fields for an entry being added.
func (k *Keyring) normalizeEntry(e *Entry) {
	if e.KeyID == "" {
		e.KeyID = fingerprint(e.PublicKey)
	}
	now := time.Now().UTC()
	if e.Created.IsZero() {
		e.Created = now
	}
	if e.ValidFrom.IsZero() {
		e.ValidFrom = now
	}
	if e.Status == "" {
		e.Status = StatusActive
	}
}

// fingerprint is the hex-encoded SHA-256 of the public key, used as key_id and
// to match the published key lifecycle's fingerprint identity.
func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Shared auth error sentinels, aliased for brevity within the package.
var (
	errInvalidFormat = autherrors.ErrInvalidKeyFormat
	errDecryptFailed = autherrors.ErrKeyDecryptFailed
)
