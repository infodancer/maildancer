package domain

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// limitStore is the backing store for authentication rate-limit counters and
// lockout markers (#206). Two implementations exist: redisLimitStore, which
// shares state across every daemon and survives process restarts, and
// memLimitStore, which is the test double and the fallback when no Redis
// client is configured.
//
// Expiry is the store's job, via a TTL set when a key is created. There is no
// sweep: the previous in-memory limiter needed a background goroutine to prune
// its timestamp slices, and TTL-based expiry replaces it outright.
//
// Lockout markers carry no value -- their presence is the fact -- so the
// interface needs no get. Keys with policy payloads arrive with the peer-ban
// keyspace in a later phase, and that lives in session-manager, not here.
type limitStore interface {
	// incr increments key and returns the new value, applying ttl when it
	// creates the key. An expired or absent key starts a fresh window at 1.
	incr(ctx context.Context, key string, ttl time.Duration) (int64, error)

	// exists reports whether key is present and unexpired.
	exists(ctx context.Context, key string) (bool, error)

	// set writes key as a marker with the given ttl, overwriting any existing
	// value and ttl.
	set(ctx context.Context, key string, ttl time.Duration) error

	// del removes keys. Absent keys are not an error.
	del(ctx context.Context, keys ...string) error
}

// redisLimitStore implements limitStore against Redis, so counters and
// lockouts are shared by every process that authenticates -- the whole point
// of moving off per-process maps, since the measured attack hits imapd and
// pop3d from the same addresses in the same window.
type redisLimitStore struct {
	client *redis.Client
}

// newRedisLimitStore returns a limitStore backed by client.
func newRedisLimitStore(client *redis.Client) *redisLimitStore {
	return &redisLimitStore{client: client}
}

// incr uses INCR plus a conditional EXPIRE, matching the established pattern
// in internal/smtpd/smtp/ratelimit.go. The two commands are not atomic
// together, but the race is benign: if two processes INCR a new key
// concurrently, both see a count and the first EXPIRE wins.
func (s *redisLimitStore) incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		// Best-effort: a failed EXPIRE leaves a key without a TTL, which
		// over-counts until an operator notices, rather than under-counting.
		_ = s.client.Expire(ctx, key, ttl).Err()
	}
	return n, nil
}

func (s *redisLimitStore) exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *redisLimitStore) set(ctx context.Context, key string, ttl time.Duration) error {
	return s.client.Set(ctx, key, "1", ttl).Err()
}

func (s *redisLimitStore) del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	err := s.client.Del(ctx, keys...).Err()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	return err
}

// memLimitStore is an in-process limitStore. It is the test double and the
// fallback when Redis is not configured; it deliberately does not share state
// across processes, so a deployment running on it gets per-process limiting
// only. now is injectable so tests can advance time without sleeping.
type memLimitStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*memLimitEntry
}

type memLimitEntry struct {
	count     int64
	expiresAt time.Time
}

func newMemLimitStore() *memLimitStore {
	return &memLimitStore{
		now:     time.Now,
		entries: make(map[string]*memLimitEntry),
	}
}

// live returns the unexpired entry for key, deleting it if it has expired.
// Callers must hold the lock. Expiry on access is what keeps the map from
// growing without a sweep goroutine; a key that is never touched again is
// dropped by pruneLocked below.
func (s *memLimitStore) live(key string) *memLimitEntry {
	e := s.entries[key]
	if e == nil {
		return nil
	}
	if !s.now().Before(e.expiresAt) {
		delete(s.entries, key)
		return nil
	}
	return e
}

// pruneLocked drops every expired entry. Expiry-on-access alone would leak
// entries for keys that are never revisited -- a spray from many source
// addresses touches each key once -- so writes also sweep. Callers must hold
// the lock.
func (s *memLimitStore) pruneLocked() {
	now := s.now()
	for key, e := range s.entries {
		if !now.Before(e.expiresAt) {
			delete(s.entries, key)
		}
	}
}

func (s *memLimitStore) incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked()
	if e := s.live(key); e != nil {
		e.count++
		return e.count, nil
	}
	s.entries[key] = &memLimitEntry{count: 1, expiresAt: s.now().Add(ttl)}
	return 1, nil
}

func (s *memLimitStore) exists(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live(key) != nil, nil
}

func (s *memLimitStore) set(_ context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked()
	s.entries[key] = &memLimitEntry{count: 1, expiresAt: s.now().Add(ttl)}
	return nil
}

func (s *memLimitStore) del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range keys {
		delete(s.entries, key)
	}
	return nil
}

// size reports the number of stored entries. Test-only; it exists so the TTL
// tests can assert that expiry actually reclaims memory now that there is no
// sweep goroutine to observe.
func (s *memLimitStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	return len(s.entries)
}
