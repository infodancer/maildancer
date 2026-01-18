package msgstore

// EncryptionInfo contains metadata about message encryption.
// This is stored in the Envelope to track encryption state.
// Note: msgstore never performs encryption or decryption.
// smtpd encrypts before delivery, pop3d decrypts after retrieval.
type EncryptionInfo struct {
	// Algorithm identifies the encryption algorithm used.
	// Example: "x25519-xsalsa20-poly1305" (NaCl box)
	Algorithm string

	// Encrypted indicates whether the message content is encrypted.
	Encrypted bool
}
