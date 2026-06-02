package notify

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMailChannel_Deterministic(t *testing.T) {
	a := MailChannel("alice@example.com")
	b := MailChannel("alice@example.com")
	if a != b {
		t.Errorf("MailChannel not deterministic: %q != %q", a, b)
	}
}

func TestMailChannel_CaseInsensitive(t *testing.T) {
	a := MailChannel("Alice@Example.COM")
	b := MailChannel("alice@example.com")
	if a != b {
		t.Errorf("MailChannel not case-insensitive: %q != %q", a, b)
	}
}

func TestMailChannel_Format(t *testing.T) {
	ch := MailChannel("test@example.com")
	if len(ch) != len("mail:new:")+32 {
		t.Errorf("unexpected channel length: %d (%q)", len(ch), ch)
	}
	if ch[:9] != "mail:new:" {
		t.Errorf("unexpected prefix: %q", ch[:9])
	}
}

func TestMailChannel_DifferentAddresses(t *testing.T) {
	a := MailChannel("alice@example.com")
	b := MailChannel("bob@example.com")
	if a == b {
		t.Error("different addresses produced the same channel")
	}
}

func TestNewSubscriber_EmptyURL(t *testing.T) {
	s, err := NewSubscriber("", "", slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != nil {
		t.Error("expected nil subscriber for empty URL")
	}
}

func TestNewSubscriber_InvalidURL(t *testing.T) {
	_, err := NewSubscriber("not-a-url", "", slog.Default())
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestNilSubscriber_Subscribe(t *testing.T) {
	var s *Subscriber
	sub := s.Subscribe(context.Background(), "test@example.com")
	if sub != nil {
		t.Error("expected nil subscription from nil subscriber")
	}
}

func TestNilSubscriber_Close(t *testing.T) {
	var s *Subscriber
	if err := s.Close(); err != nil {
		t.Errorf("unexpected error closing nil subscriber: %v", err)
	}
}

func TestNilSubscription_Close(t *testing.T) {
	var sub *Subscription
	if err := sub.Close(); err != nil {
		t.Errorf("unexpected error closing nil subscription: %v", err)
	}
}

func TestSubscription_ReceivesMessage(t *testing.T) {
	mr := miniredis.RunT(t)

	sub, err := NewSubscriber("redis://"+mr.Addr(), "", slog.Default())
	if err != nil {
		t.Fatalf("NewSubscriber: %v", err)
	}
	defer func() { _ = sub.Close() }()

	ctx := context.Background()
	subscription := sub.Subscribe(ctx, "alice@example.com")
	defer func() { _ = subscription.Close() }()

	// Allow subscription to be established
	time.Sleep(50 * time.Millisecond)

	// Publish from a separate client (simulating smtpd)
	pub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = pub.Close() }()

	channel := MailChannel("alice@example.com")
	if err := pub.Publish(ctx, channel, "INBOX").Err(); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg := <-subscription.C:
		if msg.Payload != "INBOX" {
			t.Errorf("payload = %q, want %q", msg.Payload, "INBOX")
		}
		if msg.Channel != channel {
			t.Errorf("channel = %q, want %q", msg.Channel, channel)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestSubscription_IgnoresOtherUsers(t *testing.T) {
	mr := miniredis.RunT(t)

	sub, err := NewSubscriber("redis://"+mr.Addr(), "", slog.Default())
	if err != nil {
		t.Fatalf("NewSubscriber: %v", err)
	}
	defer func() { _ = sub.Close() }()

	ctx := context.Background()
	subscription := sub.Subscribe(ctx, "alice@example.com")
	defer func() { _ = subscription.Close() }()

	time.Sleep(50 * time.Millisecond)

	// Publish to bob's channel
	pub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = pub.Close() }()

	bobChannel := MailChannel("bob@example.com")
	if err := pub.Publish(ctx, bobChannel, "INBOX").Err(); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg := <-subscription.C:
		t.Fatalf("received unexpected message: %v", msg)
	case <-time.After(200 * time.Millisecond):
		// Expected: alice should not receive bob's notification
	}
}
