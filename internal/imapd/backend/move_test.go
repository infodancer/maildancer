package backend

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/infodancer/maildancer/internal/imapd/config"
)

// learnRecord captures a single rspamd learn request.
type learnRecord struct {
	Endpoint string
	User     string
	Body     string
}

// rspamdStub serves as a test double for rspamd's controller.
type rspamdStub struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records []learnRecord
}

func newRspamdStub() *rspamdStub {
	s := &rspamdStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.records = append(s.records, learnRecord{
			Endpoint: r.URL.Path,
			User:     r.Header.Get("Rcpt"),
			Body:     string(body),
		})
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return s
}

func (s *rspamdStub) close() { s.srv.Close() }

func (s *rspamdStub) getRecords() []learnRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]learnRecord, len(s.records))
	copy(result, s.records)
	return result
}

func TestTriggerLearn_ToJunk_LearnSpam(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "Subject: spam\r\n\r\nBuy now!")

	rspamd := newRspamdStub()
	defer rspamd.close()

	s := &Session{
		store:       store,
		folderStore: store,
		mailbox:     "testuser@example.com",
		username:    "testuser@example.com",
		learner:     newSpamLearner(rspamd.srv.URL, ""),
		logger:      slog.Default(),
	}

	msgs, _ := store.List(context.Background(), s.mailbox)
	s.triggerLearn(context.Background(), "INBOX", msgs[0].UID, true)

	records := rspamd.getRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 learn call, got %d", len(records))
	}
	if records[0].Endpoint != "/learnspam" {
		t.Errorf("endpoint = %q, want /learnspam", records[0].Endpoint)
	}
	if records[0].User != "testuser@example.com" {
		t.Errorf("user = %q, want testuser@example.com", records[0].User)
	}
	if !strings.Contains(records[0].Body, "Buy now!") {
		t.Errorf("body should contain message content, got %q", records[0].Body)
	}
}

func TestTriggerLearn_FromJunk_LearnHam(t *testing.T) {
	store := newMockStore()
	_ = store.CreateFolder(context.Background(), "testuser@example.com", "Junk")
	store.addFolderMessage("testuser@example.com", "Junk", nil, "Subject: legit\r\n\r\nNot spam")

	rspamd := newRspamdStub()
	defer rspamd.close()

	s := &Session{
		store:       store,
		folderStore: store,
		mailbox:     "testuser@example.com",
		username:    "testuser@example.com",
		learner:     newSpamLearner(rspamd.srv.URL, ""),
		logger:      slog.Default(),
	}

	msgs, _ := store.ListInFolder(context.Background(), s.mailbox, "Junk")
	s.triggerLearn(context.Background(), "Junk", msgs[0].UID, false)

	records := rspamd.getRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 learn call, got %d", len(records))
	}
	if records[0].Endpoint != "/learnham" {
		t.Errorf("endpoint = %q, want /learnham", records[0].Endpoint)
	}
	if records[0].User != "testuser@example.com" {
		t.Errorf("user = %q, want testuser@example.com", records[0].User)
	}
}

func TestTriggerLearn_RspamdError_DoesNotPanic(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "Subject: test\r\n\r\nbody")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	s := &Session{
		store:       store,
		folderStore: store,
		mailbox:     "testuser@example.com",
		username:    "testuser@example.com",
		learner:     newSpamLearner(srv.URL, ""),
		logger:      slog.Default(),
	}

	msgs, _ := store.List(context.Background(), s.mailbox)
	// Should log a warning but not panic or return an error.
	s.triggerLearn(context.Background(), "INBOX", msgs[0].UID, true)
}

func TestTriggerLearn_MissingMessage_DoesNotPanic(t *testing.T) {
	store := newMockStore()

	rspamd := newRspamdStub()
	defer rspamd.close()

	s := &Session{
		store:       store,
		folderStore: store,
		mailbox:     "testuser@example.com",
		username:    "testuser@example.com",
		learner:     newSpamLearner(rspamd.srv.URL, ""),
		logger:      slog.Default(),
	}

	// Non-existent UID — should log warning, not panic.
	s.triggerLearn(context.Background(), "INBOX", 99999, true)

	records := rspamd.getRecords()
	if len(records) != 0 {
		t.Errorf("expected no learn calls for missing message, got %d", len(records))
	}
}

func TestJunkFolderName_Default(t *testing.T) {
	s := &Session{}
	if got := s.junkFolderName(); got != "Junk" {
		t.Errorf("junkFolderName() = %q, want Junk", got)
	}
}

func TestJunkFolderName_Configured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rspamd.JunkFolder = "Spam"
	s := &Session{cfg: cfg}
	if got := s.junkFolderName(); got != "Spam" {
		t.Errorf("junkFolderName() = %q, want Spam", got)
	}
}

func TestLearnDirection(t *testing.T) {
	if got := learnDirection(true); got != "spam" {
		t.Errorf("learnDirection(true) = %q, want spam", got)
	}
	if got := learnDirection(false); got != "ham" {
		t.Errorf("learnDirection(false) = %q, want ham", got)
	}
}
