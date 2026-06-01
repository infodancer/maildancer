package msgstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/box"

	autherrors "github.com/infodancer/auth/errors"
)

// mockDeliveryAgent records deliveries for testing.
type mockDeliveryAgent struct {
	deliveries []mockDelivery
}

type mockDelivery struct {
	envelope Envelope
	message  []byte
}

func (m *mockDeliveryAgent) Deliver(ctx context.Context, envelope Envelope, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	m.deliveries = append(m.deliveries, mockDelivery{
		envelope: envelope,
		message:  data,
	})
	return nil
}

// mockKeyProvider provides keys for testing.
type mockKeyProvider struct {
	keys map[string][]byte
}

func (m *mockKeyProvider) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	key, ok := m.keys[username]
	if !ok {
		return nil, autherrors.ErrKeyNotFound
	}
	return key, nil
}

func (m *mockKeyProvider) HasEncryption(ctx context.Context, username string) (bool, error) {
	_, ok := m.keys[username]
	return ok, nil
}

// generateTestKeyPair generates an X25519 key pair for testing.
func generateTestKeyPair() (publicKey, privateKey []byte) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub[:], priv[:]
}

func TestEncryptingDeliveryAgent_PlaintextOnly(t *testing.T) {
	underlying := &mockDeliveryAgent{}
	keyProvider := &mockKeyProvider{keys: make(map[string][]byte)}

	agent := NewEncryptingDeliveryAgent(underlying, keyProvider)

	ctx := context.Background()
	envelope := Envelope{
		From:       "sender@example.com",
		Recipients: []string{"plaintext@example.com"},
	}
	message := []byte("Hello, World!")

	err := agent.Deliver(ctx, envelope, bytes.NewReader(message))
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if len(underlying.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(underlying.deliveries))
	}

	d := underlying.deliveries[0]
	if d.envelope.Encryption != nil {
		t.Error("expected no encryption info for plaintext delivery")
	}
	if !bytes.Equal(d.message, message) {
		t.Errorf("message mismatch: got %q, want %q", d.message, message)
	}
}

func TestEncryptingDeliveryAgent_EncryptedOnly(t *testing.T) {
	underlying := &mockDeliveryAgent{}

	// Generate key pair for recipient
	pubKey, privKey := generateTestKeyPair()
	keyProvider := &mockKeyProvider{
		keys: map[string][]byte{
			"encrypted": pubKey,
		},
	}

	agent := NewEncryptingDeliveryAgent(underlying, keyProvider)

	ctx := context.Background()
	envelope := Envelope{
		From:       "sender@example.com",
		Recipients: []string{"encrypted@example.com"},
	}
	message := []byte("Secret message!")

	err := agent.Deliver(ctx, envelope, bytes.NewReader(message))
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if len(underlying.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(underlying.deliveries))
	}

	d := underlying.deliveries[0]
	if d.envelope.Encryption == nil {
		t.Fatal("expected encryption info for encrypted delivery")
	}
	if !d.envelope.Encryption.Encrypted {
		t.Error("expected Encrypted to be true")
	}
	if d.envelope.Encryption.Algorithm != EncryptionAlgorithm {
		t.Errorf("algorithm = %q, want %q", d.envelope.Encryption.Algorithm, EncryptionAlgorithm)
	}

	// Verify we can decrypt the message
	decrypted, err := DecryptMessage(d.message, privKey)
	if err != nil {
		t.Fatalf("DecryptMessage failed: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted message mismatch: got %q, want %q", decrypted, message)
	}
}

func TestEncryptingDeliveryAgent_MixedRecipients(t *testing.T) {
	underlying := &mockDeliveryAgent{}

	// Generate key pair for encrypted recipient only
	pubKey, privKey := generateTestKeyPair()
	keyProvider := &mockKeyProvider{
		keys: map[string][]byte{
			"encrypted": pubKey,
		},
	}

	agent := NewEncryptingDeliveryAgent(underlying, keyProvider)

	ctx := context.Background()
	envelope := Envelope{
		From:       "sender@example.com",
		Recipients: []string{"plaintext@example.com", "encrypted@example.com"},
	}
	message := []byte("Message for both!")

	err := agent.Deliver(ctx, envelope, bytes.NewReader(message))
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Should have 2 deliveries: one plaintext, one encrypted
	if len(underlying.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries, got %d", len(underlying.deliveries))
	}

	// Find plaintext and encrypted deliveries
	var plaintextDelivery, encryptedDelivery *mockDelivery
	for i := range underlying.deliveries {
		d := &underlying.deliveries[i]
		if d.envelope.Encryption == nil {
			plaintextDelivery = d
		} else {
			encryptedDelivery = d
		}
	}

	if plaintextDelivery == nil {
		t.Fatal("missing plaintext delivery")
	}
	if encryptedDelivery == nil {
		t.Fatal("missing encrypted delivery")
	}

	// Check plaintext delivery
	if len(plaintextDelivery.envelope.Recipients) != 1 {
		t.Errorf("plaintext recipients = %v, want 1 recipient", plaintextDelivery.envelope.Recipients)
	}
	if plaintextDelivery.envelope.Recipients[0] != "plaintext@example.com" {
		t.Errorf("plaintext recipient = %q, want %q", plaintextDelivery.envelope.Recipients[0], "plaintext@example.com")
	}
	if !bytes.Equal(plaintextDelivery.message, message) {
		t.Errorf("plaintext message mismatch")
	}

	// Check encrypted delivery
	if len(encryptedDelivery.envelope.Recipients) != 1 {
		t.Errorf("encrypted recipients = %v, want 1 recipient", encryptedDelivery.envelope.Recipients)
	}
	if encryptedDelivery.envelope.Recipients[0] != "encrypted@example.com" {
		t.Errorf("encrypted recipient = %q, want %q", encryptedDelivery.envelope.Recipients[0], "encrypted@example.com")
	}

	// Verify decryption
	decrypted, err := DecryptMessage(encryptedDelivery.message, privKey)
	if err != nil {
		t.Fatalf("DecryptMessage failed: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted message mismatch")
	}
}

func TestEncryptingDeliveryAgent_SubaddressRecipient(t *testing.T) {
	underlying := &mockDeliveryAgent{}

	// Key is stored under "encrypted" (the base username without +tag)
	pubKey, privKey := generateTestKeyPair()
	keyProvider := &mockKeyProvider{
		keys: map[string][]byte{
			"encrypted": pubKey,
		},
	}

	agent := NewEncryptingDeliveryAgent(underlying, keyProvider)

	ctx := context.Background()
	envelope := Envelope{
		From:       "sender@example.com",
		Recipients: []string{"encrypted+folder@example.com"},
	}
	message := []byte("Subaddressed secret!")

	err := agent.Deliver(ctx, envelope, bytes.NewReader(message))
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	if len(underlying.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(underlying.deliveries))
	}

	d := underlying.deliveries[0]
	if d.envelope.Encryption == nil {
		t.Fatal("expected encryption info for subaddressed recipient")
	}
	if !d.envelope.Encryption.Encrypted {
		t.Error("expected Encrypted to be true")
	}

	// The envelope recipient should preserve the original +tag address
	if d.envelope.Recipients[0] != "encrypted+folder@example.com" {
		t.Errorf("recipient = %q, want %q", d.envelope.Recipients[0], "encrypted+folder@example.com")
	}

	// Verify we can decrypt with the base user's key
	decrypted, err := DecryptMessage(d.message, privKey)
	if err != nil {
		t.Fatalf("DecryptMessage failed: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted message mismatch: got %q, want %q", decrypted, message)
	}
}

func TestDecryptMessage_InvalidData(t *testing.T) {
	_, privKey := generateTestKeyPair()

	t.Run("too short", func(t *testing.T) {
		_, err := DecryptMessage([]byte("short"), privKey)
		if err == nil {
			t.Error("expected error for short data")
		}
	})

	t.Run("invalid ciphertext", func(t *testing.T) {
		// Create data that's long enough but has invalid ciphertext
		data := make([]byte, PublicKeySize+NonceSize+box.Overhead+10)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		_, err := DecryptMessage(data, privKey)
		if err == nil {
			t.Error("expected error for invalid ciphertext")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		// Encrypt with one key pair
		pubKey1, _ := generateTestKeyPair()
		_, privKey2 := generateTestKeyPair()

		message := []byte("test message")
		encrypted, err := encryptMessage(message, pubKey1)
		if err != nil {
			t.Fatalf("encryptMessage failed: %v", err)
		}

		// Try to decrypt with different key
		_, err = DecryptMessage(encrypted, privKey2)
		if err == nil {
			t.Error("expected error when decrypting with wrong key")
		}
	})
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "user"},
		{"alice@mail.example.org", "alice"},
		{"localuser", "localuser"},
		{"user+tag@example.com", "user+tag"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := extractUsername(tt.email)
			if result != tt.expected {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.email, result, tt.expected)
			}
		})
	}
}
