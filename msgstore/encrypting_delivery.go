package msgstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const (
	// EncryptionAlgorithm is the algorithm identifier for encrypted messages.
	EncryptionAlgorithm = "x25519-xsalsa20-poly1305"

	// PublicKeySize is the size of an X25519 public key.
	PublicKeySize = 32

	// NonceSize is the size of the NaCl box nonce.
	NonceSize = 24
)

// EncryptingDeliveryAgent wraps a DeliveryAgent to encrypt messages before delivery.
// It uses the KeyProvider to look up recipient public keys.
// Messages are encrypted per-recipient using NaCl box (X25519 + XSalsa20-Poly1305).
type EncryptingDeliveryAgent struct {
	// underlying is the wrapped delivery agent.
	underlying DeliveryAgent

	// keyProvider provides recipient public keys.
	keyProvider KeyProvider
}

// NewEncryptingDeliveryAgent creates a new encrypting delivery agent.
// underlying is the delivery agent to wrap.
// keyProvider is used to look up recipient public keys.
func NewEncryptingDeliveryAgent(underlying DeliveryAgent, keyProvider KeyProvider) *EncryptingDeliveryAgent {
	return &EncryptingDeliveryAgent{
		underlying:  underlying,
		keyProvider: keyProvider,
	}
}

// Deliver encrypts the message for each recipient and delivers it.
// If a recipient has encryption enabled, the message is encrypted with their public key.
// If a recipient does not have encryption enabled, the message is delivered as plaintext.
// Note: This implementation delivers a single encrypted copy. For per-recipient encryption
// with different keys, the envelope is modified to contain a single recipient per delivery.
func (e *EncryptingDeliveryAgent) Deliver(ctx context.Context, envelope Envelope, message io.Reader) error {
	// Read the full message content
	messageData, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	// Group recipients by encryption status
	var encryptedRecipients []string
	var plaintextRecipients []string

	recipientKeys := make(map[string][]byte)

	for _, recipient := range envelope.Recipients {
		// Extract local part of email for key lookup
		username := extractUsername(recipient)

		hasEncryption, err := e.keyProvider.HasEncryption(ctx, username)
		if err != nil {
			// If we can't determine encryption status, treat as plaintext
			plaintextRecipients = append(plaintextRecipients, recipient)
			continue
		}

		if hasEncryption {
			pubKey, err := e.keyProvider.GetPublicKey(ctx, username)
			if err != nil {
				// If we can't get the key, treat as plaintext
				plaintextRecipients = append(plaintextRecipients, recipient)
				continue
			}
			encryptedRecipients = append(encryptedRecipients, recipient)
			recipientKeys[recipient] = pubKey
		} else {
			plaintextRecipients = append(plaintextRecipients, recipient)
		}
	}

	// Deliver plaintext messages
	if len(plaintextRecipients) > 0 {
		plaintextEnvelope := envelope
		plaintextEnvelope.Recipients = plaintextRecipients
		plaintextEnvelope.Encryption = nil

		if err := e.underlying.Deliver(ctx, plaintextEnvelope, bytes.NewReader(messageData)); err != nil {
			return err
		}
	}

	// Deliver encrypted messages (one per recipient with unique ephemeral key)
	for _, recipient := range encryptedRecipients {
		pubKey := recipientKeys[recipient]

		encryptedData, err := encryptMessage(messageData, pubKey)
		if err != nil {
			return fmt.Errorf("encrypt for %s: %w", recipient, err)
		}

		encEnvelope := envelope
		encEnvelope.Recipients = []string{recipient}
		encEnvelope.Encryption = &EncryptionInfo{
			Algorithm: EncryptionAlgorithm,
			Encrypted: true,
		}

		if err := e.underlying.Deliver(ctx, encEnvelope, bytes.NewReader(encryptedData)); err != nil {
			return err
		}
	}

	return nil
}

// encryptMessage encrypts message data using NaCl box with an ephemeral key pair.
// Returns: ephemeral_public_key (32B) || nonce (24B) || ciphertext
func encryptMessage(message []byte, recipientPubKey []byte) ([]byte, error) {
	if len(recipientPubKey) != PublicKeySize {
		return nil, fmt.Errorf("invalid recipient public key size: %d", len(recipientPubKey))
	}

	// Generate ephemeral key pair
	ephemeralPub, ephemeralPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Generate nonce
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Convert recipient public key to array
	var recipientKey [PublicKeySize]byte
	copy(recipientKey[:], recipientPubKey)

	// Encrypt the message
	ciphertext := box.Seal(nil, message, &nonce, &recipientKey, ephemeralPriv)

	// Build output: ephemeral_pub (32B) || nonce (24B) || ciphertext
	result := make([]byte, PublicKeySize+NonceSize+len(ciphertext))
	copy(result[:PublicKeySize], ephemeralPub[:])
	copy(result[PublicKeySize:PublicKeySize+NonceSize], nonce[:])
	copy(result[PublicKeySize+NonceSize:], ciphertext)

	return result, nil
}

// DecryptMessage decrypts an encrypted message using the recipient's private key.
// Input format: ephemeral_public_key (32B) || nonce (24B) || ciphertext
func DecryptMessage(encryptedData []byte, privateKey []byte) ([]byte, error) {
	if len(privateKey) != PublicKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(privateKey))
	}

	minSize := PublicKeySize + NonceSize + box.Overhead
	if len(encryptedData) < minSize {
		return nil, fmt.Errorf("encrypted data too short: %d < %d", len(encryptedData), minSize)
	}

	// Parse components
	var ephemeralPub [PublicKeySize]byte
	copy(ephemeralPub[:], encryptedData[:PublicKeySize])

	var nonce [NonceSize]byte
	copy(nonce[:], encryptedData[PublicKeySize:PublicKeySize+NonceSize])

	ciphertext := encryptedData[PublicKeySize+NonceSize:]

	// Convert private key to array
	var privKey [PublicKeySize]byte
	copy(privKey[:], privateKey)

	// Decrypt
	plaintext, ok := box.Open(nil, ciphertext, &nonce, &ephemeralPub, &privKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}

// extractUsername extracts the local part from an email address.
// Returns the full address if no @ is found.
func extractUsername(email string) string {
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			return email[:i]
		}
	}
	return email
}
