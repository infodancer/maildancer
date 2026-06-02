package smtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// spamtrapLearner sends messages to rspamd's controller API for Bayes training.
type spamtrapLearner struct {
	controllerURL string
	password      string
	client        *http.Client
}

func newSpamtrapLearner(controllerURL, password string) *spamtrapLearner {
	return &spamtrapLearner{
		controllerURL: controllerURL,
		password:      password,
		client:        &http.Client{Timeout: 10 * time.Second},
	}
}

// learnSpam sends a message to rspamd as spam training data.
func (l *spamtrapLearner) learnSpam(ctx context.Context, recipient string, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.controllerURL+"/learnspam", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if recipient != "" {
		req.Header.Set("Rcpt", recipient)
	}
	if l.password != "" {
		req.Header.Set("Password", l.password)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rspamd returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ipRateLimiter tracks per-IP event counts within a rolling hour window.
type ipRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]*rateBucket
	maxRate int
}

type rateBucket struct {
	count   int
	resetAt time.Time
}

func newIPRateLimiter(maxPerHour int) *ipRateLimiter {
	return &ipRateLimiter{
		counts:  make(map[string]*rateBucket),
		maxRate: maxPerHour,
	}
}

// allow returns true if the IP is under the rate limit and increments the counter.
func (r *ipRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, ok := r.counts[ip]
	if !ok || now.After(bucket.resetAt) {
		r.counts[ip] = &rateBucket{count: 1, resetAt: now.Add(time.Hour)}
		return true
	}
	if bucket.count >= r.maxRate {
		return false
	}
	bucket.count++
	return true
}

// cleanup removes expired entries to prevent unbounded memory growth.
// Called periodically (e.g. every 10 minutes).
func (r *ipRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for ip, bucket := range r.counts {
		if now.After(bucket.resetAt) {
			delete(r.counts, ip)
		}
	}
}
