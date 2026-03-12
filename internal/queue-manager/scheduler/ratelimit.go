package scheduler

import (
	"path/filepath"
	"time"

	"github.com/infodancer/maildancer/internal/queue-manager/config"
)

// domainLimiter manages per-domain token buckets for rate limiting.
type domainLimiter struct {
	cfg     config.RateLimitConfig
	buckets map[string]*tokenBucket
}

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	rate     float64   // tokens per second
	burst    float64   // max tokens
	tokens   float64   // current available tokens
	lastTime time.Time // last refill time
}

// newDomainLimiter creates a rate limiter from the given config.
// Returns nil if rate limiting is completely disabled (default unlimited
// with no per-domain overrides).
func newDomainLimiter(cfg config.RateLimitConfig) *domainLimiter {
	if cfg.MessagesPerHour == 0 && len(cfg.Domains) == 0 {
		return nil
	}
	return &domainLimiter{
		cfg:     cfg,
		buckets: make(map[string]*tokenBucket),
	}
}

// allow checks whether n messages can be sent to the given domain.
// Returns true and consumes tokens if allowed; returns false otherwise.
func (dl *domainLimiter) allow(domain string, n int) bool {
	b := dl.bucket(domain)
	if b == nil {
		return true
	}
	return b.allow(n)
}

// bucket returns or creates a token bucket for the domain.
// Returns nil if the domain is unlimited.
func (dl *domainLimiter) bucket(domain string) *tokenBucket {
	mph := dl.cfg.MessagesPerHour
	burst := dl.cfg.Burst

	if override, ok := dl.cfg.Domains[domain]; ok {
		mph = override.MessagesPerHour
		if override.Burst > 0 {
			burst = override.Burst
		}
	}

	if mph == 0 {
		return nil
	}

	b, ok := dl.buckets[domain]
	if !ok {
		r := float64(mph) / 3600.0
		b = &tokenBucket{
			rate:     r,
			burst:    float64(burst),
			tokens:   float64(burst),
			lastTime: time.Now(),
		}
		dl.buckets[domain] = b
	}
	return b
}

// allow checks if n tokens are available, consuming them if so.
func (b *tokenBucket) allow(n int) bool {
	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastTime = now

	needed := float64(n)
	if needed > b.tokens {
		return false
	}
	b.tokens -= needed
	return true
}

// domainFromPath extracts an FQDN from a queue domain directory path.
// Path format: .../env/{tld}/{domain} → domain.tld
func domainFromPath(domainPath string) string {
	domain := filepath.Base(domainPath)
	tld := filepath.Base(filepath.Dir(domainPath))
	return domain + "." + tld
}
