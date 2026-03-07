package rspamd_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/mail-session/rspamd"
)

func TestLearnSpam_OK(t *testing.T) {
	var gotPath, gotUser, gotCT string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUser = r.Header.Get("User")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	msg := []byte("From: spam@bad.example\r\n\r\nBuy now!\r\n")
	if err := c.LearnSpam(context.Background(), "alice@example.com", msg); err != nil {
		t.Fatalf("LearnSpam: %v", err)
	}

	if gotPath != "/learnspam" {
		t.Errorf("path = %q, want /learnspam", gotPath)
	}
	if gotUser != "alice@example.com" {
		t.Errorf("User header = %q, want alice@example.com", gotUser)
	}
	if gotCT != "message/rfc822" {
		t.Errorf("Content-Type = %q, want message/rfc822", gotCT)
	}
	if string(gotBody) != string(msg) {
		t.Errorf("body mismatch: got %q, want %q", gotBody, msg)
	}
}

func TestLearnHam_OK(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	if err := c.LearnHam(context.Background(), "bob@example.com", []byte("hello")); err != nil {
		t.Fatalf("LearnHam: %v", err)
	}
	if gotPath != "/learnham" {
		t.Errorf("path = %q, want /learnham", gotPath)
	}
}

func TestLearn_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	err := c.LearnSpam(context.Background(), "u@d.com", []byte("msg"))
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to mention 500", err)
	}
}

func TestLearn_ServerUnavailable(t *testing.T) {
	c := rspamd.New("http://127.0.0.1:1") // nothing listening
	err := c.LearnSpam(context.Background(), "u@d.com", []byte("msg"))
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestLearn_EmptyUser_NoUserHeader(t *testing.T) {
	var gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("User")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	if err := c.LearnHam(context.Background(), "", []byte("msg")); err != nil {
		t.Fatalf("LearnHam: %v", err)
	}
	if gotUser != "" {
		t.Errorf("User header = %q, want empty", gotUser)
	}
}
