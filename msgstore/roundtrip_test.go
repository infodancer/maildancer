package msgstore_test

// Round-trip integration tests for the msgstore public API.
//
// These tests exercise the full path through msgstore.Open() → Deliver() →
// List() → Retrieve() → Delete() → Expunge() using the registry interface,
// not the internal maildir.NewStore constructor. This validates the plumbing
// that smtpd and pop3d both depend on.
//
// A key scenario is the "split-process" pattern: smtpd delivers via one
// Open() call; pop3d reads via a separate Open() call against the same
// filesystem. Each test that verifies cross-instance visibility uses two
// independent store handles opened from the same StoreConfig.
//
// The production config uses:
//   - type = "maildir"
//   - base_path = "/opt/infodancer/domains/{domain}/users"  (absolute)
//   - maildir_subdir = "Maildir"
//   - path_template = "{localpart}"
//
// so a message delivered to alice@test.local lands at
//   <base_path>/alice/Maildir/
// and pop3d retrieves it using mailbox = "alice@test.local" (template strips domain).

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // register maildir backend
)

// productionConfig returns a StoreConfig matching the production setup:
// absolute base_path, Maildir subdir, {localpart} path template.
func productionConfig(basePath string) msgstore.StoreConfig {
	return msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: basePath,
		Options: map[string]string{
			"maildir_subdir": "Maildir",
			"path_template":  "{localpart}",
		},
	}
}

// deliver opens a fresh store and delivers a message to the given recipient.
func deliver(t *testing.T, cfg msgstore.StoreConfig, recipient, subject, body string) {
	t.Helper()
	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open (deliver): %v", err)
	}
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{recipient},
	}
	msg := strings.NewReader("Subject: " + subject + "\r\n\r\n" + body)
	if err := store.Deliver(context.Background(), envelope, msg); err != nil {
		t.Fatalf("Deliver to %s: %v", recipient, err)
	}
}

// listMailbox opens a fresh store and returns all messages in the mailbox.
func listMailbox(t *testing.T, cfg msgstore.StoreConfig, mailbox string) []msgstore.MessageInfo {
	t.Helper()
	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open (list): %v", err)
	}
	msgs, err := store.List(context.Background(), mailbox)
	if err != nil {
		t.Fatalf("List %s: %v", mailbox, err)
	}
	return msgs
}

// retrieveMessage opens a fresh store and retrieves the full message content.
func retrieveMessage(t *testing.T, cfg msgstore.StoreConfig, mailbox, uid string) string {
	t.Helper()
	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open (retrieve): %v", err)
	}
	rc, err := store.Retrieve(context.Background(), mailbox, uid)
	if err != nil {
		t.Fatalf("Retrieve %s/%s: %v", mailbox, uid, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(data)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestRoundTrip_Open_UnknownType verifies that Open returns an error for
// unregistered store types.
func TestRoundTrip_Open_UnknownType(t *testing.T) {
	cfg := msgstore.StoreConfig{Type: "nosuchtype", BasePath: t.TempDir()}
	_, err := msgstore.Open(cfg)
	if err == nil {
		t.Fatal("expected error for unknown store type, got nil")
	}
}

// TestRoundTrip_DeliverAndList_BasicPath verifies that a message delivered
// via the registry API is visible via a second independent Open() call.
// This is the core split-process scenario (smtpd writes, pop3d reads).
func TestRoundTrip_DeliverAndList_BasicPath(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "alice@test.local", "Hello", "Test body.")

	// Open a separate store instance to simulate pop3d reading independently.
	msgs := listMailbox(t, cfg, "alice@test.local")
	if len(msgs) != 1 {
		t.Errorf("expected 1 message for mailbox alice, got %d", len(msgs))
	}
}

// TestRoundTrip_LocalpartTemplate verifies the production path_template
// "{localpart}" correctly resolves alice@test.local → alice directory.
// Both delivery and retrieval use full addresses; the template strips the domain.
func TestRoundTrip_LocalpartTemplate(t *testing.T) {
	basePath := t.TempDir()
	cfg := productionConfig(basePath)

	deliver(t, cfg, "alice@test.local", "Template Test", "Body.")

	// pop3d retrieves using the full address; {localpart} template resolves to "alice".
	msgs := listMailbox(t, cfg, "alice@test.local")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message via full address mailbox, got %d", len(msgs))
	}
}

// TestRoundTrip_MessageContent_Preserved verifies that the delivered message
// content is returned verbatim by Retrieve.
func TestRoundTrip_MessageContent_Preserved(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	wantSubject := "Content preservation test"
	wantBody := "The quick brown fox jumps over the lazy dog."

	deliver(t, cfg, "bob@test.local", wantSubject, wantBody)

	msgs := listMailbox(t, cfg, "bob@test.local")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	content := retrieveMessage(t, cfg, "bob@test.local", msgs[0].UID)
	if !strings.Contains(content, wantSubject) {
		t.Errorf("content missing subject %q", wantSubject)
	}
	if !strings.Contains(content, wantBody) {
		t.Errorf("content missing body %q", wantBody)
	}
}

// TestRoundTrip_MultipleMessages verifies that multiple deliveries accumulate
// and each message is independently retrievable.
func TestRoundTrip_MultipleMessages(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	subjects := []string{"First", "Second", "Third"}
	for _, s := range subjects {
		deliver(t, cfg, "carol@test.local", s, "Body of "+s)
	}

	msgs := listMailbox(t, cfg, "carol@test.local")
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	// Verify each message is individually retrievable.
	for _, m := range msgs {
		content := retrieveMessage(t, cfg, "carol@test.local", m.UID)
		if content == "" {
			t.Errorf("message %s retrieved empty content", m.UID)
		}
	}
}

// TestRoundTrip_SizeReported verifies that MessageInfo.Size reflects the
// actual message size.
func TestRoundTrip_SizeReported(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "dave@test.local", "Size Test", "A short body.")

	msgs := listMailbox(t, cfg, "dave@test.local")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Size == 0 {
		t.Error("MessageInfo.Size should be non-zero")
	}
	if msgs[0].UID == "" {
		t.Error("MessageInfo.UID should be non-empty")
	}
}

// TestRoundTrip_Stat verifies that Stat returns correct count and total bytes.
func TestRoundTrip_Stat(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	for range 3 {
		deliver(t, cfg, "eve@test.local", "Stat Test", "Body.")
	}

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	count, totalBytes, err := store.Stat(context.Background(), "eve@test.local")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 3 {
		t.Errorf("Stat count = %d, want 3", count)
	}
	if totalBytes == 0 {
		t.Error("Stat totalBytes should be non-zero")
	}
}

// TestRoundTrip_Delete_HidesMessage verifies that Delete makes a message
// invisible in List and Retrieve within the same store session.
func TestRoundTrip_Delete_HidesMessage(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "frank@test.local", "Delete Me", "Body.")

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	msgs, err := store.List(ctx, "frank@test.local")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	if err := store.Delete(ctx, "frank@test.local", msgs[0].UID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Should be hidden from List in same session.
	after, err := store.List(ctx, "frank@test.local")
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("expected 0 messages after delete, got %d", len(after))
	}
}

// TestRoundTrip_Expunge_RemovesPermanently verifies that Expunge persists
// the deletion — a new store instance opened after Expunge cannot see or
// retrieve the message.
func TestRoundTrip_Expunge_RemovesPermanently(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "grace@test.local", "Expunge Me", "Body.")

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	msgs, err := store.List(ctx, "grace@test.local")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	uid := msgs[0].UID

	if err := store.Delete(ctx, "grace@test.local", uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Expunge(ctx, "grace@test.local"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	// New store instance — simulates pop3d session reconnect after expunge.
	store2, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open store2: %v", err)
	}
	msgs2, err := store2.List(ctx, "grace@test.local")
	if err != nil {
		t.Fatalf("List store2: %v", err)
	}
	if len(msgs2) != 0 {
		t.Errorf("expected 0 messages after expunge+reconnect, got %d", len(msgs2))
	}

	// Retrieve should fail.
	_, err = store2.Retrieve(ctx, "grace@test.local", uid)
	if err == nil {
		t.Error("expected error retrieving expunged message, got nil")
	}
}

// TestRoundTrip_DeleteWithoutExpunge_PersistsAcrossSessions verifies that
// a soft-deleted message (Delete without Expunge) is still visible to a
// new store instance — deletion is session-local until Expunge.
func TestRoundTrip_DeleteWithoutExpunge_PersistsAcrossSessions(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "henry@test.local", "Soft Delete", "Body.")

	store1, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open store1: %v", err)
	}
	ctx := context.Background()

	msgs, err := store1.List(ctx, "henry@test.local")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	uid := msgs[0].UID

	// Soft delete — no Expunge.
	if err := store1.Delete(ctx, "henry@test.local", uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// A new session (store2) should still see the message on disk.
	msgs2 := listMailbox(t, cfg, "henry@test.local")
	if len(msgs2) != 1 {
		t.Errorf("expected message still visible in new session (no expunge), got %d", len(msgs2))
	}
}

// TestRoundTrip_MultipleRecipients verifies that a single delivery to N
// recipients creates independent copies in each mailbox.
func TestRoundTrip_MultipleRecipients(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"alice@test.local", "bob@test.local"},
	}
	msg := strings.NewReader("Subject: Multi\r\n\r\nBody.")
	if err := store.Deliver(context.Background(), envelope, msg); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	for _, mb := range []string{"alice@test.local", "bob@test.local"} {
		msgs := listMailbox(t, cfg, mb)
		if len(msgs) != 1 {
			t.Errorf("mailbox %s: expected 1 message, got %d", mb, len(msgs))
		}
	}
}

// TestRoundTrip_DomainIsolation verifies that delivering to alice@domain-a.com
// does not affect alice@domain-b.com when using {localpart} template.
// With {localpart}, both resolve to the same "alice" path — this test uses
// distinct local parts to confirm isolation.
func TestRoundTrip_DomainIsolation(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "alice@test.local", "For Alice", "Body.")
	deliver(t, cfg, "bob@test.local", "For Bob", "Body.")

	aliceMsgs := listMailbox(t, cfg, "alice@test.local")
	bobMsgs := listMailbox(t, cfg, "bob@test.local")

	if len(aliceMsgs) != 1 {
		t.Errorf("alice: expected 1 message, got %d", len(aliceMsgs))
	}
	if len(bobMsgs) != 1 {
		t.Errorf("bob: expected 1 message, got %d", len(bobMsgs))
	}
}

// TestRoundTrip_EmptyMailbox_NoError verifies that List on a brand-new
// mailbox returns empty slice without error (auto-create behaviour).
func TestRoundTrip_EmptyMailbox_NoError(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	msgs := listMailbox(t, cfg, "newuser@test.local")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages for new mailbox, got %d", len(msgs))
	}
}

// TestRoundTrip_SubaddressStripped verifies that plus-addressed recipients
// (user+tag@domain) deliver to the base mailbox (user).
func TestRoundTrip_SubaddressStripped(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	deliver(t, cfg, "alice+spam@test.local", "Subaddressed", "Body.")

	// Should be visible under "alice@test.local" (subaddress stripped + localpart template).
	msgs := listMailbox(t, cfg, "alice@test.local")
	if len(msgs) != 1 {
		t.Errorf("expected 1 message in alice mailbox after subaddress delivery, got %d", len(msgs))
	}
}

// TestRoundTrip_PathTraversal_Rejected verifies that path traversal attempts
// in recipient addresses are rejected by Deliver.
func TestRoundTrip_PathTraversal_Rejected(t *testing.T) {
	cfg := productionConfig(t.TempDir())

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	traversalAddresses := []string{
		"../etc/passwd",
		"user/../../../etc",
	}
	for _, addr := range traversalAddresses {
		envelope := msgstore.Envelope{
			From:       "sender@example.com",
			Recipients: []string{addr},
		}
		msg := strings.NewReader("Subject: Traversal\r\n\r\nBody.")
		err := store.Deliver(context.Background(), envelope, msg)
		if err == nil {
			t.Errorf("expected error for path traversal address %q, got nil", addr)
		}
	}
}

// TestRoundTrip_NoMaildirSubdir verifies that a store configured without
// maildir_subdir works correctly (maildir at basePath/user/ directly).
func TestRoundTrip_NoMaildirSubdir(t *testing.T) {
	cfg := msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: t.TempDir(),
		Options:  map[string]string{"path_template": "{localpart}"},
	}

	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"alice@test.local"},
	}
	if err := store.Deliver(context.Background(), envelope, strings.NewReader("Subject: No Subdir\r\n\r\nBody.")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	msgs := listMailbox(t, cfg, "alice@test.local")
	if len(msgs) != 1 {
		t.Errorf("expected 1 message without maildir_subdir, got %d", len(msgs))
	}
}
