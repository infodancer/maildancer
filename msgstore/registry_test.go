package msgstore_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"

	// Import maildir to trigger registration
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func TestRegisteredTypes(t *testing.T) {
	types := msgstore.RegisteredTypes()
	if len(types) == 0 {
		t.Fatal("expected at least one registered type")
	}

	// maildir should be registered via init()
	found := false
	for _, typ := range types {
		if typ == "maildir" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("maildir not found in registered types: %v", types)
	}
}

func TestOpen(t *testing.T) {
	basePath := t.TempDir()

	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: basePath,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestOpenUnregistered(t *testing.T) {
	_, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "nonexistent",
		BasePath: "/tmp",
	})
	if err != errors.ErrStoreNotRegistered {
		t.Fatalf("expected ErrStoreNotRegistered, got %v", err)
	}
}

func TestOpenInvalidConfig(t *testing.T) {
	_, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: "", // invalid - empty path
	})
	if err != errors.ErrStoreConfigInvalid {
		t.Fatalf("expected ErrStoreConfigInvalid, got %v", err)
	}
}

func TestMsgStoreInterface(t *testing.T) {
	basePath := t.TempDir()

	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: basePath,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	ctx := context.Background()
	mailbox := "test@example.com"

	// Test Deliver (DeliveryAgent)
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{mailbox},
	}
	message := strings.NewReader("Subject: Test\r\n\r\nTest body")

	if err := store.Deliver(ctx, envelope, message); err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}

	// Test List (MessageStore)
	messages, err := store.List(ctx, mailbox)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	// Test Retrieve (MessageStore)
	reader, err := store.Retrieve(ctx, mailbox, messages[0].UID)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	data, _ := io.ReadAll(reader)
	_ = reader.Close()
	if !strings.Contains(string(data), "Test body") {
		t.Fatal("message content not found")
	}

	// Test Stat (MessageStore)
	count, bytes, err := store.Stat(ctx, mailbox)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
	if bytes == 0 {
		t.Fatal("expected non-zero bytes")
	}

	// Test Delete (MessageStore)
	if err := store.Delete(ctx, mailbox, messages[0].UID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Test Expunge (MessageStore)
	if err := store.Expunge(ctx, mailbox); err != nil {
		t.Fatalf("Expunge failed: %v", err)
	}

	// Verify message is gone
	messages, err = store.List(ctx, mailbox)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(messages) != 0 {
		t.Fatalf("expected 0 messages after expunge, got %d", len(messages))
	}
}
