package domain

import (
	"context"
	"log/slog"
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

// Redis key prefixes for the authentication limiter. Counters and lockout
// markers are separate keys so a lockout outlives the window that earned it.
// The peer-ban keyspace (peer:*) belongs to session-manager and is not
// written here.
const (
	keyFailIPUser = "auth:fail:ipuser:"
	keyFailIP     = "auth:fail:ip:"
	keyLockIPUser = "auth:lock:ipuser:"
	keyLockIP     = "auth:lock:ip:"
)

// RateLimitConfig holds thresholds for authentication rate limiting.
type RateLimitConfig struct {
	// MaxFailuresPerIPUser is the max failed attempts for a single (IP, username)
	// pair within the window before lockout. Default: 5.
	MaxFailuresPerIPUser int

	// MaxFailuresPerIP is the max failed attempts from a single IP (across all
	// usernames) within the window before lockout. Default: 20.
	MaxFailuresPerIP int

	// Window is how long a failure counts toward a threshold. Default: 5 minutes.
	Window time.Duration

	// Lockout is how long to block after the threshold is exceeded. Default: 15 minutes.
	Lockout time.Duration
}

// DefaultRateLimitConfig returns sensible defaults for auth rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxFailuresPerIPUser: 5,
		MaxFailuresPerIP:     20,
		Window:               5 * time.Minute,
		Lockout:              15 * time.Minute,
	}
}

// authRateLimiter tracks failed authentication attempts across two dimensions:
// (IP, username) and per-IP.
//
// There is deliberately no per-username dimension. Locking an account across
// all source addresses is a cheap denial of service against a real user: the
// attack measured in #206 was distributed across 59 addresses, so an attacker
// could lock any known account out for the price of a handful of requests.
// Since every username in that traffic was nonexistent, a username-keyed
// lockout would also have protected nothing. Aggregate per-username failure
// counts are worth alerting on, but not enforcing.
//
// Consequently an empty client IP disables this limiter entirely -- there is
// no dimension left to key on. Callers must set the IP with WithClientIP.
//
// This limiter covers wrong-password-on-a-real-account only: the graduated,
// DoS-sensitive case. The nonexistent-account signal is handled by the
// peer-ban path in session-manager, which bans on the first attempt rather
// than counting.
type authRateLimiter struct {
	cfg   RateLimitConfig
	store limitStore
}

func newAuthRateLimiter(cfg RateLimitConfig, store limitStore) *authRateLimiter {
	return &authRateLimiter{cfg: cfg, store: store}
}

// ipUserKey builds the (IP, username) key suffix. The separator cannot occur
// in either component, so distinct pairs cannot collide.
func ipUserKey(ip, username string) string {
	return ip + "\x00" + username
}

// isLimited reports whether the given IP and username are currently locked out.
//
// It fails open on store errors: a Redis outage disables bruteforce protection,
// which is bad, but failing closed would lock out every legitimate user for the
// duration of the same outage, which is the outcome the attacker wants anyway.
// Errors are logged at warn so the fail-open is visible rather than silent.
func (rl *authRateLimiter) isLimited(ctx context.Context, ip, username string) bool {
	if ip == "" {
		return false
	}

	keys := make([]string, 0, 2)
	if username != "" {
		keys = append(keys, keyLockIPUser+ipUserKey(ip, username))
	}
	keys = append(keys, keyLockIP+ip)

	for _, key := range keys {
		locked, err := rl.store.exists(ctx, key)
		if err != nil {
			slog.Warn("auth rate limit check failed, allowing attempt",
				"error", err.Error(), "ip", ip)
			return false
		}
		if locked {
			return true
		}
	}
	return false
}

// recordFailure records a failed authentication attempt and writes a lockout
// marker if a threshold is reached. Store errors are logged and otherwise
// ignored, for the same fail-open reason as isLimited.
func (rl *authRateLimiter) recordFailure(ctx context.Context, ip, username string) {
	if ip == "" {
		return
	}

	if username != "" {
		rl.count(ctx, keyFailIPUser+ipUserKey(ip, username),
			keyLockIPUser+ipUserKey(ip, username), rl.cfg.MaxFailuresPerIPUser)
	}
	rl.count(ctx, keyFailIP+ip, keyLockIP+ip, rl.cfg.MaxFailuresPerIP)
}

// count increments the failure counter at counterKey and, once it reaches
// maxFailures, writes the lockout marker at lockKey.
func (rl *authRateLimiter) count(ctx context.Context, counterKey, lockKey string, maxFailures int) {
	if maxFailures <= 0 {
		return
	}

	n, err := rl.store.incr(ctx, counterKey, rl.cfg.Window)
	if err != nil {
		slog.Warn("auth failure counter increment failed",
			"error", err.Error(), "key", counterKey)
		return
	}
	if n < int64(maxFailures) {
		return
	}
	if err := rl.store.set(ctx, lockKey, rl.cfg.Lockout); err != nil {
		slog.Warn("auth lockout write failed",
			"error", err.Error(), "key", lockKey)
	}
}

// recordSuccess clears the (IP, username) failure counter and lockout, so a
// successful login resets that pair.
//
// The per-IP counter is deliberately left alone: one account authenticating
// successfully should not reset the limit for other accounts being attacked
// from the same address.
func (rl *authRateLimiter) recordSuccess(ctx context.Context, ip, username string) {
	if ip == "" || username == "" {
		return
	}
	pair := ipUserKey(ip, username)
	if err := rl.store.del(ctx, keyFailIPUser+pair, keyLockIPUser+pair); err != nil {
		slog.Warn("auth failure counter reset failed",
			"error", err.Error(), "ip", ip)
	}
}
