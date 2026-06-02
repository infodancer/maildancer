package smtp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/redis/go-redis/v9"
)

// Notifier publishes new-mail notifications to Redis pub/sub.
// It is safe for concurrent use by multiple sessions.
type Notifier struct {
	client *redis.Client
	logger *slog.Logger
}

// NewNotifier creates a Notifier from a Redis URL.
// Returns nil if url is empty (notifications disabled).
func NewNotifier(url, password string, logger *slog.Logger) (*Notifier, error) {
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
	return &Notifier{
		client: redis.NewClient(opts),
		logger: logger,
	}, nil
}

// NewNotifierFromClient creates a Notifier from an existing Redis client.
// The caller retains ownership of the client — Close on the Notifier is a no-op
// for the underlying connection.
func NewNotifierFromClient(client *redis.Client, logger *slog.Logger) *Notifier {
	return &Notifier{
		client: client,
		logger: logger,
	}
}

// Close shuts down the Redis client.
func (n *Notifier) Close() error {
	if n == nil {
		return nil
	}
	return n.client.Close()
}

// NotifyNewMail publishes a new-mail notification for the given recipient and folder.
// Errors are logged but never returned — delivery must not fail due to notifications.
func (n *Notifier) NotifyNewMail(ctx context.Context, recipient, folder string) {
	if n == nil {
		return
	}
	channel := MailChannel(recipient)
	if err := n.client.Publish(ctx, channel, folder).Err(); err != nil {
		n.logger.Warn("redis publish failed",
			slog.String("channel", channel),
			slog.String("error", err.Error()))
	}
}

// MailChannel returns the Redis pub/sub channel name for a recipient address.
// Format: mail:new:<hex(sha256(lowercase(addr))[:16])>
// The hash prevents leaking email addresses to anyone with Redis access.
func MailChannel(addr string) string {
	h := sha256.Sum256([]byte(strings.ToLower(addr)))
	return "mail:new:" + hex.EncodeToString(h[:16])
}
