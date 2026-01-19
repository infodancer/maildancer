package rspamd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

func TestNewChecker(t *testing.T) {
	checker := NewChecker("http://localhost:11333", "secret", 10*time.Second)

	if checker.baseURL != "http://localhost:11333" {
		t.Errorf("expected baseURL http://localhost:11333, got %s", checker.baseURL)
	}
	if checker.password != "secret" {
		t.Errorf("expected password secret, got %s", checker.password)
	}
	if checker.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", checker.httpClient.Timeout)
	}
}

func TestNewChecker_TrimsTrailingSlash(t *testing.T) {
	checker := NewChecker("http://localhost:11333/", "", 10*time.Second)

	if checker.baseURL != "http://localhost:11333" {
		t.Errorf("expected baseURL without trailing slash, got %s", checker.baseURL)
	}
}

func TestChecker_Name(t *testing.T) {
	checker := NewChecker("http://localhost:11333", "", 10*time.Second)
	if checker.Name() != "rspamd" {
		t.Errorf("expected name 'rspamd', got %s", checker.Name())
	}
}

func TestChecker_Check(t *testing.T) {
	tests := []struct {
		name           string
		response       RspamdResult
		statusCode     int
		wantErr        bool
		expectedScore  float64
		expectedAction spamcheck.Action
	}{
		{
			name: "ham message",
			response: RspamdResult{
				Score:         1.5,
				RequiredScore: 15.0,
				Action:        RspamdActionNoAction,
				IsSpam:        false,
			},
			statusCode:     http.StatusOK,
			wantErr:        false,
			expectedScore:  1.5,
			expectedAction: spamcheck.ActionAccept,
		},
		{
			name: "spam message",
			response: RspamdResult{
				Score:         20.5,
				RequiredScore: 15.0,
				Action:        RspamdActionReject,
				IsSpam:        true,
			},
			statusCode:     http.StatusOK,
			wantErr:        false,
			expectedScore:  20.5,
			expectedAction: spamcheck.ActionReject,
		},
		{
			name: "greylist message",
			response: RspamdResult{
				Score:         5.0,
				RequiredScore: 15.0,
				Action:        RspamdActionGreylist,
				IsSpam:        false,
			},
			statusCode:     http.StatusOK,
			wantErr:        false,
			expectedScore:  5.0,
			expectedAction: spamcheck.ActionTempFail,
		},
		{
			name: "soft reject message",
			response: RspamdResult{
				Score:         8.0,
				RequiredScore: 15.0,
				Action:        RspamdActionSoftReject,
				IsSpam:        false,
			},
			statusCode:     http.StatusOK,
			wantErr:        false,
			expectedScore:  8.0,
			expectedAction: spamcheck.ActionTempFail,
		},
		{
			name: "add header message",
			response: RspamdResult{
				Score:         10.0,
				RequiredScore: 15.0,
				Action:        RspamdActionAddHeader,
				IsSpam:        false,
			},
			statusCode:     http.StatusOK,
			wantErr:        false,
			expectedScore:  10.0,
			expectedAction: spamcheck.ActionFlag,
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/checkv2" {
					t.Errorf("expected path /checkv2, got %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					if err := json.NewEncoder(w).Encode(tt.response); err != nil {
						t.Fatalf("failed to encode response: %v", err)
					}
				}
			}))
			defer server.Close()

			checker := NewChecker(server.URL, "", 10*time.Second)
			result, err := checker.Check(context.Background(), strings.NewReader("test message"), spamcheck.CheckOptions{
				From:       "sender@example.com",
				Recipients: []string{"recipient@example.com"},
				IP:         "192.168.1.1",
				Helo:       "client.example.com",
			})

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Score != tt.expectedScore {
				t.Errorf("expected score %.2f, got %.2f", tt.expectedScore, result.Score)
			}
			if result.Action != tt.expectedAction {
				t.Errorf("expected action %s, got %s", tt.expectedAction, result.Action)
			}
			if result.CheckerName != "rspamd" {
				t.Errorf("expected checker name 'rspamd', got %s", result.CheckerName)
			}
		})
	}
}

func TestChecker_Check_Headers(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(RspamdResult{Score: 1.0, Action: RspamdActionNoAction}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	checker := NewChecker(server.URL, "testpass", 10*time.Second)
	_, err := checker.Check(context.Background(), strings.NewReader("test"), spamcheck.CheckOptions{
		From:       "sender@example.com",
		Recipients: []string{"rcpt1@example.com", "rcpt2@example.com"},
		IP:         "10.0.0.1",
		Helo:       "mail.example.com",
		Hostname:   "server.example.com",
		User:       "testuser",
		QueueID:    "ABC123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check headers were set correctly
	if receivedHeaders.Get("From") != "sender@example.com" {
		t.Errorf("expected From header sender@example.com, got %s", receivedHeaders.Get("From"))
	}
	if receivedHeaders.Get("IP") != "10.0.0.1" {
		t.Errorf("expected IP header 10.0.0.1, got %s", receivedHeaders.Get("IP"))
	}
	if receivedHeaders.Get("Helo") != "mail.example.com" {
		t.Errorf("expected Helo header mail.example.com, got %s", receivedHeaders.Get("Helo"))
	}
	if receivedHeaders.Get("Hostname") != "server.example.com" {
		t.Errorf("expected Hostname header server.example.com, got %s", receivedHeaders.Get("Hostname"))
	}
	if receivedHeaders.Get("User") != "testuser" {
		t.Errorf("expected User header testuser, got %s", receivedHeaders.Get("User"))
	}
	if receivedHeaders.Get("Queue-Id") != "ABC123" {
		t.Errorf("expected Queue-Id header ABC123, got %s", receivedHeaders.Get("Queue-Id"))
	}
	if receivedHeaders.Get("Password") != "testpass" {
		t.Errorf("expected Password header testpass, got %s", receivedHeaders.Get("Password"))
	}

	// Check multiple recipients
	rcpts := receivedHeaders.Values("Rcpt")
	if len(rcpts) != 2 {
		t.Errorf("expected 2 Rcpt headers, got %d", len(rcpts))
	}
}

func TestChecker_Ping(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "success",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/ping" {
					t.Errorf("expected path /ping, got %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			checker := NewChecker(server.URL, "", 10*time.Second)
			err := checker.Ping(context.Background())

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestChecker_Close(t *testing.T) {
	checker := NewChecker("http://localhost:11333", "", 10*time.Second)
	err := checker.Close()
	if err != nil {
		t.Errorf("expected no error from Close(), got %v", err)
	}
}

func TestCheckResult_ShouldReject(t *testing.T) {
	tests := []struct {
		name      string
		result    spamcheck.CheckResult
		threshold float64
		want      bool
	}{
		{
			name:      "action reject",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionReject, Score: 10.0},
			threshold: 15.0,
			want:      true,
		},
		{
			name:      "score above threshold",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionAccept, Score: 20.0},
			threshold: 15.0,
			want:      true,
		},
		{
			name:      "score below threshold",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionAccept, Score: 5.0},
			threshold: 15.0,
			want:      false,
		},
		{
			name:      "threshold disabled",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionAccept, Score: 20.0},
			threshold: 0,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ShouldReject(tt.threshold); got != tt.want {
				t.Errorf("ShouldReject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckResult_ShouldTempFail(t *testing.T) {
	tests := []struct {
		name      string
		result    spamcheck.CheckResult
		threshold float64
		want      bool
	}{
		{
			name:      "action tempfail",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionTempFail, Score: 5.0},
			threshold: 10.0,
			want:      true,
		},
		{
			name:      "score above threshold",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionAccept, Score: 12.0},
			threshold: 10.0,
			want:      true,
		},
		{
			name:      "score below threshold",
			result:    spamcheck.CheckResult{Action: spamcheck.ActionAccept, Score: 5.0},
			threshold: 10.0,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ShouldTempFail(tt.threshold); got != tt.want {
				t.Errorf("ShouldTempFail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChecker_BuildHeaders(t *testing.T) {
	checker := NewChecker("http://localhost:11333", "", 10*time.Second)

	t.Run("spam message headers", func(t *testing.T) {
		result := &RspamdResult{
			Score:         15.5,
			RequiredScore: 15.0,
			Action:        RspamdActionReject,
			IsSpam:        true,
		}

		headers := checker.buildHeaders(result)

		if headers["X-Spam-Status"] != "Yes, score=15.50 required=15.00" {
			t.Errorf("unexpected X-Spam-Status: %s", headers["X-Spam-Status"])
		}
		if headers["X-Spam-Score"] != "15.50" {
			t.Errorf("unexpected X-Spam-Score: %s", headers["X-Spam-Score"])
		}
		if headers["X-Spam-Flag"] != "YES" {
			t.Errorf("unexpected X-Spam-Flag: %s", headers["X-Spam-Flag"])
		}
		if headers["X-Spam-Checker"] != "rspamd" {
			t.Errorf("unexpected X-Spam-Checker: %s", headers["X-Spam-Checker"])
		}
	})

	t.Run("ham message headers", func(t *testing.T) {
		result := &RspamdResult{
			Score:         2.5,
			RequiredScore: 15.0,
			Action:        RspamdActionNoAction,
			IsSpam:        false,
		}

		headers := checker.buildHeaders(result)

		if headers["X-Spam-Status"] != "No, score=2.50 required=15.00" {
			t.Errorf("unexpected X-Spam-Status: %s", headers["X-Spam-Status"])
		}
		if headers["X-Spam-Flag"] != "NO" {
			t.Errorf("unexpected X-Spam-Flag: %s", headers["X-Spam-Flag"])
		}
	})
}
