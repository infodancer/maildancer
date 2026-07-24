package smtp

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// newBufferingSession builds a session that delivers into the mock, with spam
// checking left off so Data takes the "no spam check" buffering branch.
func newBufferingSession(t *testing.T, mock *combinedMockServer) *Session {
	t.Helper()
	agent := startCombinedMockServer(t, mock)
	return &Session{
		backend: &Backend{
			hostname:   "mail.example.com",
			smDelivery: agent,
			logger:     slog.Default(),
			tempDir:    t.TempDir(),
			spamConfig: config.SpamCheckConfig{Enabled: false},
		},
		logger:       slog.Default(),
		from:         "sender@external.com",
		recipients:   []string{"bob@example.com"},
		mailFromSeen: true,
	}
}

// TestData_NoSpamCheckBuffersMessageOnce covers the regression in issue #183:
// the temp buffer is filled by the TeeReader as the message is read, so draining
// the reader into that same buffer stored every message twice. Only the trace
// headers we prepend may appear ahead of the message; the message itself must
// appear exactly once.
func TestData_NoSpamCheckBuffersMessageOnce(t *testing.T) {
	mock := &combinedMockServer{}
	s := newBufferingSession(t, mock)

	msg := "From: sender@external.com\r\nSubject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.delivers) != 1 {
		t.Fatalf("expected 1 local delivery, got %d", len(mock.delivers))
	}
	body := mock.delivers[0].body

	if n := strings.Count(body, "Subject: hello"); n != 1 {
		t.Errorf("message stored %d times, want 1:\n%s", n, body)
	}
	if n := strings.Count(body, "body\r\n"); n != 1 {
		t.Errorf("body stored %d times, want 1:\n%s", n, body)
	}
	if !strings.HasSuffix(body, msg) {
		t.Errorf("delivered message is not the trace headers followed by exactly the original message:\n%s", body)
	}
}

// TestData_NoSpamCheckBuffersMessageOnce_Remote covers the same branch on the
// outbound queue path, which shares the buffer.
func TestData_NoSpamCheckBuffersMessageOnce_Remote(t *testing.T) {
	mock := &combinedMockServer{validateLocal: map[string]bool{"remote@elsewhere.example": false}}
	s := newBufferingSession(t, mock)
	s.recipients = nil
	s.remoteRecipients = []string{"remote@elsewhere.example"}

	msg := "Subject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.enqueues) != 1 {
		t.Fatalf("expected 1 enqueue, got %d", len(mock.enqueues))
	}
	if body := mock.enqueues[0].body; !strings.HasSuffix(body, msg) || strings.Count(body, "Subject: hello") != 1 {
		t.Errorf("queued message was not stored exactly once:\n%s", body)
	}
}

// TestData_ReportedSizeMatchesStoredMessage pins the other half of #183: the
// logged size comes from countingReader, which counts reads rather than stores.
// It agreed with the message while the stored copy was double, which is why the
// duplication never showed up in the logs. Sizes must now agree.
func TestData_ReportedSizeMatchesStoredMessage(t *testing.T) {
	mock := &combinedMockServer{}
	s := newBufferingSession(t, mock)

	msg := "Subject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	body := mock.delivers[0].body

	// Everything after the trace headers we prepended is the stored message.
	stored := body[strings.Index(body, "Subject: hello"):]
	if len(stored) != len(msg) {
		t.Errorf("stored message is %d bytes, but %d were read from the client", len(stored), len(msg))
	}
}
