package msgstore

import "context"

// KeyProvider retrieves public keys for message encryption.
// Used by msgstore to encrypt messages before writing to disk.
type KeyProvider interface {
	// GetPublicKey returns the public key for encrypting messages to a mailbox.
	// Returns an error if no key is available for the mailbox.
	GetPublicKey(ctx context.Context, mailbox string) ([]byte, error)
}

// EncryptionInfo contains metadata about message encryption.
type EncryptionInfo struct {
	// Algorithm identifies the encryption algorithm used.
	// Example: "x25519-xsalsa20-poly1305" (NaCl box)
	Algorithm string

	// Encrypted indicates whether the message content is encrypted.
	Encrypted bool
}
