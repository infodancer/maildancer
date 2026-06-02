// Package notify provides Redis pub/sub integration for IMAP IDLE notifications.
package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/redis/go-redis/v9"
)

// MailChannel returns the Redis pub/sub channel name for a recipient address.
// Format: mail:new:<hex(sha256(lowercase(addr))[:16])>
// Must match the publisher side in smtpd.
func MailChannel(addr string) string {
	h := sha256.Sum256([]byte(strings.ToLower(addr)))
	return "mail:new:" + hex.EncodeToString(h[:16])
}

// Subscriber listens for new-mail notifications on a per-user Redis channel.
type Subscriber struct {
	client *redis.Client
	logger *slog.Logger
}

// NewSubscriber creates a Subscriber from a Redis URL.
// Returns nil if url is empty (notifications disabled).
func NewSubscriber(url, password string, logger *slog.Logger) (*Subscriber, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if password != "" {
		opts.Password = password
	}
	return &Subscriber{
		client: redis.NewClient(opts),
		logger: logger,
	}, nil
}

// Close shuts down the Redis client.
func (s *Subscriber) Close() error {
	if s == nil {
		return nil
	}
	return s.client.Close()
}

// Subscription represents an active pub/sub subscription for a single user.
// Messages are delivered to the C channel. Call Close to unsubscribe.
type Subscription struct {
	pubsub *redis.PubSub
	C      <-chan *redis.Message
}

// Subscribe starts listening for new-mail notifications for the given email address.
// Returns nil if the Subscriber is nil (notifications disabled).
func (s *Subscriber) Subscribe(ctx context.Context, email string) *Subscription {
	if s == nil {
		return nil
	}
	channel := MailChannel(email)
	pubsub := s.client.Subscribe(ctx, channel)
	return &Subscription{
		pubsub: pubsub,
		C:      pubsub.Channel(),
	}
}

// Close unsubscribes and releases resources.
func (sub *Subscription) Close() error {
	if sub == nil {
		return nil
	}
	return sub.pubsub.Close()
}
