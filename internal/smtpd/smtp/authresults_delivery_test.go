package smtp

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// fakeChecker stands in for rspamd, returning a fixed verdict. The mapping from
// rspamd symbols to the field value is tested in the rspamd package; what
// matters here is that whatever a checker reports actually reaches the delivered
// message.
type fakeChecker struct {
	authResults string
}

func (f *fakeChecker) Name() string { return "fake" }
func (f *fakeChecker) Close() error { return nil }

func (f *fakeChecker) Check(_ context.Context, message io.Reader, _ spamcheck.CheckOptions) (*spamcheck.CheckResult, error) {
	// A real checker consumes the message; the session relies on that to fill
	// its temp buffer via the TeeReader.
	if _, err := io.Copy(io.Discard, message); err != nil {
		return nil, err
	}
	return &spamcheck.CheckResult{
		CheckerName: "fake",
		Action:      spamcheck.ActionAccept,
		AuthResults: f.authResults,
	}, nil
}

// newStampingSession builds a session whose local deliveries land in the mock,
// with spam checking enabled so the Authentication-Results path is exercised.
func newStampingSession(t *testing.T, mock *combinedMockServer, authResults string) *Session {
	t.Helper()
	agent := startCombinedMockServer(t, mock)
	backend := &Backend{
		hostname:   "mail.infodancer.net",
		smDelivery: agent,
		logger:     slog.Default(),
		tempDir:    t.TempDir(),
		spamChecker: &fakeChecker{
			authResults: authResults,
		},
		spamConfig: config.SpamCheckConfig{
			Enabled:  true,
			Checkers: []config.SpamCheckerConfig{{Type: "rspamd", URL: "http://unused"}},
		},
	}
	return &Session{
		backend:      backend,
		logger:       slog.Default(),
		from:         "sender@external.com",
		recipients:   []string{"bob@example.com"},
		mailFromSeen: true,
	}
}

// deliveredBody returns the single local delivery the mock recorded.
func deliveredBody(t *testing.T, mock *combinedMockServer) string {
	t.Helper()
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.delivers) != 1 {
		t.Fatalf("expected 1 local delivery, got %d", len(mock.delivers))
	}
	return mock.delivers[0].body
}

// TestData_StampsAuthResultsOnLocalDelivery is the end-to-end case for issue
// #123: a message accepted and delivered locally must carry the checker's
// verdicts as an Authentication-Results header.
func TestData_StampsAuthResultsOnLocalDelivery(t *testing.T) {
	mock := &combinedMockServer{}
	s := newStampingSession(t, mock, "mail.infodancer.net;\r\n\tspf=pass smtp.mailfrom=external.com;\r\n\tdkim=pass header.d=external.com")

	msg := "From: sender@external.com\r\nSubject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	body := deliveredBody(t, mock)
	if !strings.Contains(body, "Authentication-Results: mail.infodancer.net;\r\n\tspf=pass smtp.mailfrom=external.com;\r\n\tdkim=pass header.d=external.com\r\n") {
		t.Errorf("delivered message is missing the stamped header:\n%s", body)
	}

	// RFC 8601: the header must precede the message's own headers, so the
	// topmost Authentication-Results is the one this MTA stamped.
	arIdx := strings.Index(body, "Authentication-Results:")
	fromIdx := strings.Index(body, "From: sender@external.com")
	if arIdx < 0 || fromIdx < 0 || arIdx > fromIdx {
		t.Errorf("header was not prepended (ar=%d from=%d):\n%s", arIdx, fromIdx, body)
	}

	// It belongs to our own trace hop, so it sits directly below our Received.
	recvIdx := strings.Index(body, "Received: from")
	if recvIdx < 0 || recvIdx > arIdx {
		t.Errorf("Authentication-Results is not below our Received header:\n%s", body)
	}
}

// TestData_NoVerdictsNoHeader proves silence is not stamped as a verdict: when
// the checker reports nothing, no header is added at all. A header asserting
// zero results would read as "checked, nothing passed".
func TestData_NoVerdictsNoHeader(t *testing.T) {
	mock := &combinedMockServer{}
	s := newStampingSession(t, mock, "")

	if err := s.Data(strings.NewReader("Subject: hello\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Data: %v", err)
	}

	if body := deliveredBody(t, mock); strings.Contains(body, "Authentication-Results") {
		t.Errorf("stamped a header with no verdicts to report:\n%s", body)
	}
}

// TestData_StripsForgedAuthResults is the security case: a message arriving with
// a forged Authentication-Results claiming our authserv-id must have it removed,
// leaving exactly the one we stamped. Otherwise anything not reading strictly
// the topmost header sees the attacker's verdict.
func TestData_StripsForgedAuthResults(t *testing.T) {
	mock := &combinedMockServer{}
	s := newStampingSession(t, mock, "mail.infodancer.net;\r\n\tdkim=fail header.d=evil.example")

	msg := "From: attacker@evil.example\r\n" +
		"Authentication-Results: mail.infodancer.net; dkim=pass header.d=paypal.com\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass header.d=elsewhere.example\r\n" +
		"Subject: your account\r\n" +
		"\r\n" +
		"body\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	body := deliveredBody(t, mock)
	if strings.Contains(body, "dkim=pass header.d=paypal.com") {
		t.Errorf("forged header bearing our authserv-id survived:\n%s", body)
	}
	if !strings.Contains(body, "dkim=fail header.d=evil.example") {
		t.Errorf("our own verdict is missing:\n%s", body)
	}
	if !strings.Contains(body, "Authentication-Results: mx.google.com;") {
		t.Errorf("another ADMD's header was wrongly removed:\n%s", body)
	}
	if n := strings.Count(body, "mail.infodancer.net;"); n != 1 {
		t.Errorf("expected exactly 1 header with our authserv-id, got %d:\n%s", n, body)
	}
}

// TestData_NoStampOnOutboundRelay: a message we relay outward carries no
// Authentication-Results of ours -- our authserv-id is meaningless to the
// receiving ADMD, and stamping it would disclose our filtering verdicts.
func TestData_NoStampOnOutboundRelay(t *testing.T) {
	mock := &combinedMockServer{validateLocal: map[string]bool{"remote@elsewhere.example": false}}
	s := newStampingSession(t, mock, "mail.infodancer.net;\r\n\tspf=pass smtp.mailfrom=external.com")
	s.recipients = nil
	s.remoteRecipients = []string{"remote@elsewhere.example"}

	if err := s.Data(strings.NewReader("Subject: hello\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Data: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.enqueues) != 1 {
		t.Fatalf("expected 1 enqueue, got %d", len(mock.enqueues))
	}
	if body := mock.enqueues[0].body; strings.Contains(body, "Authentication-Results") {
		t.Errorf("stamped our verdicts on a relayed message:\n%s", body)
	}
}

// TestData_StripsForgedAuthResultsOnRelay: the strip applies to outbound relay
// too, even though nothing is stamped there -- a forged header claiming our
// authserv-id must never leave our systems asserting a verdict we did not make.
func TestData_StripsForgedAuthResultsOnRelay(t *testing.T) {
	mock := &combinedMockServer{validateLocal: map[string]bool{"remote@elsewhere.example": false}}
	s := newStampingSession(t, mock, "")
	s.recipients = nil
	s.remoteRecipients = []string{"remote@elsewhere.example"}

	msg := "Authentication-Results: mail.infodancer.net; dkim=pass header.d=paypal.com\r\n" +
		"Subject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if body := mock.enqueues[0].body; strings.Contains(body, "dkim=pass header.d=paypal.com") {
		t.Errorf("forged header left our systems on a relayed message:\n%s", body)
	}
}
