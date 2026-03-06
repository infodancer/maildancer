package smtp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

func TestIPRateLimiter_Basic(t *testing.T) {
	rl := newIPRateLimiter(3)

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Errorf("attempt %d: expected allow, got deny", i+1)
		}
	}
	// 4th should be denied
	if rl.allow("1.2.3.4") {
		t.Error("4th attempt: expected deny, got allow")
	}
	// Different IP should be allowed
	if !rl.allow("5.6.7.8") {
		t.Error("different IP: expected allow, got deny")
	}
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	rl := newIPRateLimiter(1)
	rl.allow("1.2.3.4")

	// Manually expire the bucket
	rl.mu.Lock()
	rl.counts["1.2.3.4"].resetAt = time.Now().Add(-time.Minute)
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.Lock()
	_, exists := rl.counts["1.2.3.4"]
	rl.mu.Unlock()

	if exists {
		t.Error("expected expired entry to be cleaned up")
	}
}

func TestIPRateLimiter_Reset(t *testing.T) {
	rl := newIPRateLimiter(1)
	rl.allow("1.2.3.4")

	// Should be denied
	if rl.allow("1.2.3.4") {
		t.Error("expected deny after limit reached")
	}

	// Expire the bucket
	rl.mu.Lock()
	rl.counts["1.2.3.4"].resetAt = time.Now().Add(-time.Minute)
	rl.mu.Unlock()

	// Should be allowed again after expiry
	if !rl.allow("1.2.3.4") {
		t.Error("expected allow after bucket expired")
	}
}

type learnCall struct {
	endpoint  string
	recipient string
	body      string
}

func TestSpamtrapLearner_LearnSpam(t *testing.T) {
	var mu sync.Mutex
	var calls []learnCall

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, learnCall{
			endpoint:  r.URL.Path,
			recipient: r.Header.Get("Rcpt"),
			body:      string(body),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	learner := newSpamtrapLearner(srv.URL, "")
	err := learner.learnSpam(t.Context(), "bogus@example.com", strings.NewReader("Subject: spam\r\n\r\nBuy now!"))
	if err != nil {
		t.Fatalf("learnSpam: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("expected 1 learn call, got %d", len(calls))
	}
	if calls[0].endpoint != "/learnspam" {
		t.Errorf("endpoint = %q, want /learnspam", calls[0].endpoint)
	}
	if calls[0].recipient != "bogus@example.com" {
		t.Errorf("recipient = %q, want bogus@example.com", calls[0].recipient)
	}
	if !strings.Contains(calls[0].body, "Buy now!") {
		t.Errorf("body should contain message content")
	}
}

func TestSpamtrapLearner_WithPassword(t *testing.T) {
	var gotPassword string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPassword = r.Header.Get("Password")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	learner := newSpamtrapLearner(srv.URL, "secret123")
	err := learner.learnSpam(t.Context(), "x@y.com", strings.NewReader("test"))
	if err != nil {
		t.Fatalf("learnSpam: %v", err)
	}
	if gotPassword != "secret123" {
		t.Errorf("password = %q, want secret123", gotPassword)
	}
}

func TestSpamtrapLearner_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	learner := newSpamtrapLearner(srv.URL, "")
	err := learner.learnSpam(t.Context(), "x@y.com", strings.NewReader("test"))
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestSpamtrapConfig_Defaults(t *testing.T) {
	cfg := config.SpamtrapConfig{}
	if got := cfg.GetMaxLearnsPerIPPerHour(); got != 10 {
		t.Errorf("default max learns = %d, want 10", got)
	}

	cfg.MaxLearnsPerIPPerHour = 25
	if got := cfg.GetMaxLearnsPerIPPerHour(); got != 25 {
		t.Errorf("custom max learns = %d, want 25", got)
	}
}

func TestRejectionMode_GetRejectionMode(t *testing.T) {
	tests := []struct {
		input config.RejectionMode
		want  config.RejectionMode
	}{
		{"", config.RejectionModeRcpt},
		{config.RejectionModeRcpt, config.RejectionModeRcpt},
		{config.RejectionModeData, config.RejectionModeData},
		{"invalid", config.RejectionModeRcpt},
	}
	for _, tt := range tests {
		cfg := config.Config{RecipientRejection: tt.input}
		if got := cfg.GetRejectionMode(); got != tt.want {
			t.Errorf("GetRejectionMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
