package backend

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestSpamLearner_LearnSpam(t *testing.T) {
	var mu sync.Mutex
	var gotEndpoint, gotUser, gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotEndpoint = r.URL.Path
		gotUser = r.Header.Get("Rcpt")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	learner := newSpamLearner(srv.URL, "")
	err := learner.learnSpam(t.Context(), "user@example.com", strings.NewReader("Subject: spam\r\n\r\nspam body"))
	if err != nil {
		t.Fatalf("learnSpam: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotEndpoint != "/learn_spam" {
		t.Errorf("endpoint = %q, want /learn_spam", gotEndpoint)
	}
	if gotUser != "user@example.com" {
		t.Errorf("user = %q, want user@example.com", gotUser)
	}
	if !strings.Contains(gotBody, "spam body") {
		t.Errorf("body = %q, want to contain 'spam body'", gotBody)
	}
}

func TestSpamLearner_LearnHam(t *testing.T) {
	var mu sync.Mutex
	var gotEndpoint string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotEndpoint = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	learner := newSpamLearner(srv.URL, "")
	err := learner.learnHam(t.Context(), "user@example.com", strings.NewReader("Subject: ham\r\n\r\nham body"))
	if err != nil {
		t.Fatalf("learnHam: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotEndpoint != "/learn_ham" {
		t.Errorf("endpoint = %q, want /learn_ham", gotEndpoint)
	}
}

func TestSpamLearner_Password(t *testing.T) {
	var mu sync.Mutex
	var gotPassword string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotPassword = r.Header.Get("Password")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	learner := newSpamLearner(srv.URL, "secret123")
	err := learner.learnSpam(t.Context(), "user@example.com", strings.NewReader("body"))
	if err != nil {
		t.Fatalf("learnSpam: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPassword != "secret123" {
		t.Errorf("password = %q, want secret123", gotPassword)
	}
}

func TestSpamLearner_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	learner := newSpamLearner(srv.URL, "")
	err := learner.learnSpam(t.Context(), "user@example.com", strings.NewReader("body"))
	if err == nil {
		t.Fatal("expected error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain '500'", err.Error())
	}
}
