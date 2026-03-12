package scheduler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/queue-manager/config"
)

// --- tokenBucket ---

func TestTokenBucket_AllowWithinBurst(t *testing.T) {
	b := &tokenBucket{
		rate:     10.0 / 3600.0, // 10/hour
		burst:    5,
		tokens:   5,
		lastTime: time.Now(),
	}

	if !b.allow(3) {
		t.Error("expected allow(3) = true with 5 tokens")
	}
	if !b.allow(2) {
		t.Error("expected allow(2) = true with 2 remaining tokens")
	}
	if b.allow(1) {
		t.Error("expected allow(1) = false with 0 tokens")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	b := &tokenBucket{
		rate:     1.0, // 1 per second (3600/3600)
		burst:    5,
		tokens:   0,
		lastTime: time.Now().Add(-3 * time.Second), // 3 seconds ago
	}

	if !b.allow(3) {
		t.Error("expected allow(3) = true after 3 seconds of refill at 1/sec")
	}
}

func TestTokenBucket_BurstCap(t *testing.T) {
	b := &tokenBucket{
		rate:     1.0, // 1 per second (3600/3600)
		burst:    5,
		tokens:   0,
		lastTime: time.Now().Add(-10 * time.Second), // 10 seconds ago, but burst caps at 5
	}

	if !b.allow(5) {
		t.Error("expected allow(5) = true (burst capped at 5)")
	}
	if b.allow(1) {
		t.Error("expected allow(1) = false (all burst tokens consumed)")
	}
}

func TestTokenBucket_ExceedsBurst(t *testing.T) {
	b := &tokenBucket{
		rate:     1.0, // 3600/3600
		burst:    3,
		tokens:   3,
		lastTime: time.Now(),
	}

	if b.allow(4) {
		t.Error("expected allow(4) = false when burst is 3")
	}
	// Tokens should not have been consumed on failure.
	if !b.allow(3) {
		t.Error("expected allow(3) = true after failed allow(4)")
	}
}

// --- domainLimiter ---

func TestDomainLimiter_NilWhenUnlimited(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 0,
		Burst:           10,
	})
	if dl != nil {
		t.Error("expected nil limiter when MessagesPerHour=0 and no domain overrides")
	}
}

func TestDomainLimiter_DefaultLimit(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           5,
	})

	if !dl.allow("gmail.com", 5) {
		t.Error("expected allow(5) = true with burst=5")
	}
	if dl.allow("gmail.com", 1) {
		t.Error("expected allow(1) = false after consuming all burst tokens")
	}
}

func TestDomainLimiter_PerDomainUnlimited(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           5,
		Domains: map[string]config.DomainRateLimit{
			"example.com": {MessagesPerHour: 0},
		},
	})

	// example.com is unlimited.
	if !dl.allow("example.com", 1000) {
		t.Error("expected unlimited domain to allow any count")
	}

	// Other domains still limited.
	if !dl.allow("gmail.com", 5) {
		t.Error("expected gmail.com allow(5) = true with burst=5")
	}
	if dl.allow("gmail.com", 1) {
		t.Error("expected gmail.com allow(1) = false after burst consumed")
	}
}

func TestDomainLimiter_PerDomainOverride(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           5,
		Domains: map[string]config.DomainRateLimit{
			"gmail.com": {MessagesPerHour: 50, Burst: 15},
		},
	})

	// gmail.com has higher burst.
	if !dl.allow("gmail.com", 15) {
		t.Error("expected gmail.com allow(15) = true with burst=15")
	}
	if dl.allow("gmail.com", 1) {
		t.Error("expected gmail.com allow(1) = false after burst consumed")
	}
}

func TestDomainLimiter_BurstInherit(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           5,
		Domains: map[string]config.DomainRateLimit{
			"gmail.com": {MessagesPerHour: 50}, // Burst=0 → inherit default
		},
	})

	// gmail.com should inherit default burst of 5.
	if !dl.allow("gmail.com", 5) {
		t.Error("expected gmail.com allow(5) = true with inherited burst=5")
	}
	if dl.allow("gmail.com", 1) {
		t.Error("expected gmail.com allow(1) = false after burst consumed")
	}
}

func TestDomainLimiter_IndependentBuckets(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           3,
	})

	// Drain gmail.com.
	if !dl.allow("gmail.com", 3) {
		t.Error("expected gmail.com allow(3) = true")
	}
	if dl.allow("gmail.com", 1) {
		t.Error("expected gmail.com exhausted")
	}

	// outlook.com should have its own bucket.
	if !dl.allow("outlook.com", 3) {
		t.Error("expected outlook.com allow(3) = true (independent bucket)")
	}
}

func TestDomainLimiter_UnlimitedDefaultWithDomainOverride(t *testing.T) {
	dl := newDomainLimiter(config.RateLimitConfig{
		MessagesPerHour: 0, // unlimited default
		Burst:           10,
		Domains: map[string]config.DomainRateLimit{
			"strict.com": {MessagesPerHour: 10, Burst: 2},
		},
	})

	// Default unlimited domains pass through.
	if !dl.allow("gmail.com", 1000) {
		t.Error("expected unlimited default to allow any count")
	}

	// strict.com is rate limited.
	if !dl.allow("strict.com", 2) {
		t.Error("expected strict.com allow(2) = true with burst=2")
	}
	if dl.allow("strict.com", 1) {
		t.Error("expected strict.com exhausted")
	}
}

// --- domainFromPath ---

func TestDomainFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/queue/env/com/gmail", "gmail.com"},
		{"/queue/env/org/example", "example.org"},
		{"/queue/env/net/mail", "mail.net"},
	}
	for _, c := range cases {
		got := domainFromPath(c.path)
		if got != c.want {
			t.Errorf("domainFromPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// --- integration: processDomainDir with rate limiting ---

func TestProcessDomainDir_RateLimited(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "ratelimited1234"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	// Two envelopes for the same msgid (group size = 2).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice@" + msgid + ".0", "bob@" + msgid + ".1"} {
		envFile := filepath.Join(envDir, name)
		if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-10 * time.Minute)
		if err := os.Chtimes(envFile, old, old); err != nil {
			t.Fatal(err)
		}
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	// Rate limit: burst=1, so a group of 2 envelopes should be deferred.
	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		RateLimit: config.RateLimitConfig{
			MessagesPerHour: 20,
			Burst:           1,
		},
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// mail-remote should NOT have been invoked (group needs 2 tokens, burst=1).
	if _, err := os.Stat(recordFile); !os.IsNotExist(err) {
		t.Error("expected mail-remote NOT to be invoked when rate limited")
	}

	// Envelopes should still exist (deferred, not deleted).
	for _, name := range []string{"alice@" + msgid + ".0", "bob@" + msgid + ".1"} {
		if _, err := os.Stat(filepath.Join(envDir, name)); os.IsNotExist(err) {
			t.Errorf("envelope %s should still exist after rate limiting", name)
		}
	}
}

func TestProcessDomainDir_RateLimitAllowsSmallBatch(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "allowed5678"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	// One envelope (group size = 1).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	// Rate limit: burst=1, group size=1 → should be allowed.
	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		RateLimit: config.RateLimitConfig{
			MessagesPerHour: 20,
			Burst:           1,
		},
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// mail-remote should have been invoked.
	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("expected mail-remote to be invoked: %v", err)
	}
	if !strings.Contains(string(data), msgid) {
		t.Errorf("expected args to contain msgid %q; got: %s", msgid, data)
	}
}

func TestProcessDomainDir_RateLimitPerDomainUnlimited(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "unlimited9999"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	// 5 envelopes (group size = 5).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		name := filepath.Join(envDir, "user@"+msgid+"."+string(rune('0'+i)))
		if err := os.WriteFile(name, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-10 * time.Minute)
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	// Default burst=1 (would block), but gmail.com is unlimited.
	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		RateLimit: config.RateLimitConfig{
			MessagesPerHour: 20,
			Burst:           1,
			Domains: map[string]config.DomainRateLimit{
				"gmail.com": {MessagesPerHour: 0},
			},
		},
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// mail-remote should have been invoked (gmail.com is unlimited).
	if _, err := os.Stat(recordFile); os.IsNotExist(err) {
		t.Error("expected mail-remote to be invoked for unlimited domain")
	}
}

// Tests in this file use buildFakeMailRemote from scheduler_test.go
// (same package).
