package smtp

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// senderLimiter is the interface for per-sender rate limiting.
// maxRate is passed per-call to support per-domain limits.
type senderLimiter interface {
	allow(ctx context.Context, key string, maxRate int) bool
}

// redisRateLimiter enforces per-key rate limits using Redis INCR + EXPIRE.
// Safe for use across multiple subprocesses sharing the same Redis instance.
type redisRateLimiter struct {
	client *redis.Client
	window time.Duration
	prefix string
}

// newRedisRateLimiter creates a rate limiter backed by Redis.
// prefix distinguishes different rate limit namespaces (e.g. "smtpd:sendrate:").
func newRedisRateLimiter(client *redis.Client, window time.Duration, prefix string) *redisRateLimiter {
	return &redisRateLimiter{
		client: client,
		window: window,
		prefix: prefix,
	}
}

// allow returns true if the key is under the rate limit and increments the counter.
// On Redis errors, it fails open (allows the request) to avoid blocking mail delivery.
func (r *redisRateLimiter) allow(_ context.Context, key string, maxRate int) bool {
	ctx := context.Background()
	redisKey := r.prefix + key

	// INCR + conditional EXPIRE is atomic enough: even if two subprocesses
	// race on a new key, both will INCR and the first EXPIRE wins.
	count, err := r.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return true // fail open
	}

	// Set expiry only when we just created the key (count == 1).
	if count == 1 {
		r.client.Expire(ctx, redisKey, r.window)
	}

	return count <= int64(maxRate)
}

// memRateLimiter is an in-memory rate limiter for testing.
type memRateLimiter struct {
	mu     sync.Mutex
	counts map[string]*memBucket
}

type memBucket struct {
	count   int
	resetAt time.Time
}

func newMemRateLimiter() *memRateLimiter {
	return &memRateLimiter{
		counts: make(map[string]*memBucket),
	}
}

func (r *memRateLimiter) allow(_ context.Context, key string, maxRate int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, ok := r.counts[key]
	if !ok || now.After(bucket.resetAt) {
		r.counts[key] = &memBucket{count: 1, resetAt: now.Add(time.Hour)}
		return true
	}
	if bucket.count >= maxRate {
		return false
	}
	bucket.count++
	return true
}
