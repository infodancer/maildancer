package smtp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMailChannel_Deterministic(t *testing.T) {
	ch1 := MailChannel("alice@example.com")
	ch2 := MailChannel("alice@example.com")
	if ch1 != ch2 {
		t.Errorf("MailChannel not deterministic: %q != %q", ch1, ch2)
	}
}

func TestMailChannel_CaseInsensitive(t *testing.T) {
	ch1 := MailChannel("Alice@Example.COM")
	ch2 := MailChannel("alice@example.com")
	if ch1 != ch2 {
		t.Errorf("MailChannel not case-insensitive: %q != %q", ch1, ch2)
	}
}

func TestMailChannel_Format(t *testing.T) {
	ch := MailChannel("test@example.com")
	if !strings.HasPrefix(ch, "mail:new:") {
		t.Errorf("MailChannel prefix wrong: %q", ch)
	}
	// Should be "mail:new:" + 32 hex chars (16 bytes).
	hexPart := strings.TrimPrefix(ch, "mail:new:")
	if len(hexPart) != 32 {
		t.Errorf("hex part length = %d, want 32", len(hexPart))
	}
	// Verify it matches the expected hash.
	h := sha256.Sum256([]byte("test@example.com"))
	want := hex.EncodeToString(h[:16])
	if hexPart != want {
		t.Errorf("hex = %q, want %q", hexPart, want)
	}
}

func TestMailChannel_DifferentAddresses(t *testing.T) {
	ch1 := MailChannel("alice@example.com")
	ch2 := MailChannel("bob@example.com")
	if ch1 == ch2 {
		t.Error("different addresses should produce different channels")
	}
}

func TestNotifier_PublishAndSubscribe(t *testing.T) {
	mr := miniredis.RunT(t)

	n, err := NewNotifier("redis://"+mr.Addr(), "", slog.Default())
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer func() { _ = n.Close() }()

	// Subscribe to the channel.
	ctx := context.Background()
	sub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = sub.Close() }()
	pubsub := sub.Subscribe(ctx, MailChannel("alice@example.com"))
	defer func() { _ = pubsub.Close() }()

	// Wait for subscription to be active.
	_, err = pubsub.Receive(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Publish.
	n.NotifyNewMail(ctx, "alice@example.com", "INBOX")

	// Receive.
	msg, err := pubsub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if msg.Payload != "INBOX" {
		t.Errorf("payload = %q, want INBOX", msg.Payload)
	}
	if msg.Channel != MailChannel("alice@example.com") {
		t.Errorf("channel = %q, want %q", msg.Channel, MailChannel("alice@example.com"))
	}
}

func TestNotifier_Nil_NoOp(t *testing.T) {
	// A nil Notifier should not panic.
	var n *Notifier
	n.NotifyNewMail(context.Background(), "alice@example.com", "INBOX")
	if err := n.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

func TestNewNotifier_EmptyURL(t *testing.T) {
	n, err := NewNotifier("", "", slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != nil {
		t.Error("expected nil Notifier for empty URL")
	}
}
