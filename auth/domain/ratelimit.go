package domain

import (
	"context"
	"sync"
	"time"
)

// clientIPKey is the context key for the client's IP address.
// Callers (pop3d, imapd, smtpd, session-manager) should set this before
// calling AuthenticateWithDomain so that rate limiting can track by IP.
type clientIPKeyType struct{}

// ClientIPKey is the context key used to pass the client IP address to
// the AuthRouter for rate limiting. Use WithClientIP to set it.
var ClientIPKey = clientIPKeyType{}

// WithClientIP returns a context with the client IP address set.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ClientIPKey, ip)
}

// clientIPFromContext extracts the client IP from the context.
// Returns empty string if not set.
func clientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(ClientIPKey).(string)
	return ip
}

// RateLimitConfig holds thresholds for authentication rate limiting.
type RateLimitConfig struct {
	// MaxFailuresPerIPUser is the max failed attempts for a single (IP, username)
	// pair within the window before lockout. Default: 5.
	MaxFailuresPerIPUser int

	// MaxFailuresPerIP is the max failed attempts from a single IP (across all
	// usernames) within the window before lockout. Default: 20.
	MaxFailuresPerIP int

	// MaxFailuresPerUser is the max failed attempts for a single username (across
	// all IPs) within the window before lockout. Default: 10.
	MaxFailuresPerUser int

	// Window is the sliding window for counting failures. Default: 5 minutes.
	Window time.Duration

	// Lockout is how long to block after the threshold is exceeded. Default: 15 minutes.
	Lockout time.Duration
}

// DefaultRateLimitConfig returns sensible defaults for auth rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxFailuresPerIPUser: 5,
		MaxFailuresPerIP:     20,
		MaxFailuresPerUser:   10,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}
}

// authRateLimiter tracks failed authentication attempts across three dimensions:
// (IP, username), per-IP, and per-username.
type authRateLimiter struct {
	mu     sync.Mutex
	cfg    RateLimitConfig
	now    func() time.Time // for testing
	ipUser map[string]*failureBucket
	ip     map[string]*failureBucket
	user   map[string]*failureBucket
}

// failureBucket tracks failures within a sliding window and lockout state.
type failureBucket struct {
	failures  []time.Time
	lockUntil time.Time
}

func newAuthRateLimiter(cfg RateLimitConfig) *authRateLimiter {
	return &authRateLimiter{
		cfg:    cfg,
		now:    time.Now,
		ipUser: make(map[string]*failureBucket),
		ip:     make(map[string]*failureBucket),
		user:   make(map[string]*failureBucket),
	}
}

// isLimited checks whether the given IP and username are currently rate-limited.
func (rl *authRateLimiter) isLimited(ip, username string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()

	// Check (IP, username) pair.
	if ip != "" && username != "" {
		key := ip + "\x00" + username
		if b := rl.ipUser[key]; b != nil {
			if now.Before(b.lockUntil) {
				return true
			}
		}
	}

	// Check per-IP.
	if ip != "" {
		if b := rl.ip[ip]; b != nil {
			if now.Before(b.lockUntil) {
				return true
			}
		}
	}

	// Check per-username.
	if username != "" {
		if b := rl.user[username]; b != nil {
			if now.Before(b.lockUntil) {
				return true
			}
		}
	}

	return false
}

// recordFailure records a failed authentication attempt and triggers lockout
// if thresholds are exceeded.
func (rl *authRateLimiter) recordFailure(ip, username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	cutoff := now.Add(-rl.cfg.Window)

	if ip != "" && username != "" {
		key := ip + "\x00" + username
		rl.record(rl.ipUser, key, now, cutoff, rl.cfg.MaxFailuresPerIPUser)
	}
	if ip != "" {
		rl.record(rl.ip, ip, now, cutoff, rl.cfg.MaxFailuresPerIP)
	}
	if username != "" {
		rl.record(rl.user, username, now, cutoff, rl.cfg.MaxFailuresPerUser)
	}
}

// record adds a failure timestamp to the bucket and triggers lockout if needed.
func (rl *authRateLimiter) record(m map[string]*failureBucket, key string, now, cutoff time.Time, maxFailures int) {
	b := m[key]
	if b == nil {
		b = &failureBucket{}
		m[key] = b
	}

	// Prune old entries outside the window.
	pruned := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	b.failures = append(pruned, now)

	if len(b.failures) >= maxFailures {
		b.lockUntil = now.Add(rl.cfg.Lockout)
	}
}

// recordSuccess clears failure state for the given IP and username,
// so a successful login resets the counters.
func (rl *authRateLimiter) recordSuccess(ip, username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if ip != "" && username != "" {
		delete(rl.ipUser, ip+"\x00"+username)
	}
	// Don't clear per-IP or per-user buckets on success — a successful
	// login for one account shouldn't reset limits for other accounts
	// being attacked from the same IP.
}

// cleanup removes expired entries to prevent unbounded memory growth.
// Should be called periodically (e.g., every few minutes).
func (rl *authRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	cutoff := now.Add(-rl.cfg.Window)

	cleanMap := func(m map[string]*failureBucket) {
		for key, b := range m {
			if now.After(b.lockUntil) {
				// Prune old failures.
				pruned := b.failures[:0]
				for _, t := range b.failures {
					if t.After(cutoff) {
						pruned = append(pruned, t)
					}
				}
				b.failures = pruned
				if len(b.failures) == 0 {
					delete(m, key)
				}
			}
		}
	}

	cleanMap(rl.ipUser)
	cleanMap(rl.ip)
	cleanMap(rl.user)
}
