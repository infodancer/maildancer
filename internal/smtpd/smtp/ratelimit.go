package smtp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// senderLimiter is the interface for per-sender rate limiting.
type senderLimiter interface {
	allow(ctx context.Context, key string) bool
}

// redisRateLimiter enforces per-key rate limits using Redis INCR + EXPIRE.
// Safe for use across multiple subprocesses sharing the same Redis instance.
type redisRateLimiter struct {
	client  *redis.Client
	maxRate int
	window  time.Duration
	prefix  string
}

// newRedisRateLimiter creates a rate limiter backed by Redis.
// prefix distinguishes different rate limit namespaces (e.g. "smtpd:sendrate:").
func newRedisRateLimiter(client *redis.Client, maxRate int, window time.Duration, prefix string) *redisRateLimiter {
	return &redisRateLimiter{
		client:  client,
		maxRate: maxRate,
		window:  window,
		prefix:  prefix,
	}
}

// allow returns true if the key is under the rate limit and increments the counter.
// On Redis errors, it fails open (allows the request) to avoid blocking mail delivery.
func (r *redisRateLimiter) allow(_ context.Context, key string) bool {
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

	return count <= int64(r.maxRate)
}

// memRateLimiter is an in-memory rate limiter for testing.
type memRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]*memBucket
	maxRate int
}

type memBucket struct {
	count   int
	resetAt time.Time
}

func newMemRateLimiter(maxPerHour int) *memRateLimiter {
	return &memRateLimiter{
		counts:  make(map[string]*memBucket),
		maxRate: maxPerHour,
	}
}

func (r *memRateLimiter) allow(_ context.Context, key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, ok := r.counts[key]
	if !ok || now.After(bucket.resetAt) {
		r.counts[key] = &memBucket{count: 1, resetAt: now.Add(time.Hour)}
		return true
	}
	if bucket.count >= r.maxRate {
		return false
	}
	bucket.count++
	return true
}

// remaining returns the number of sends remaining for the key, or an error.
func (r *redisRateLimiter) remaining(ctx context.Context, key string) (int, error) {
	redisKey := r.prefix + key
	count, err := r.client.Get(ctx, redisKey).Int()
	if err == redis.Nil {
		return r.maxRate, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redis get: %w", err)
	}
	rem := r.maxRate - count
	if rem < 0 {
		rem = 0
	}
	return rem, nil
}
