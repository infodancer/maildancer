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

// fakeSpamChecker returns a fixed verdict with spam headers attached, standing
// in for rspamd. The score-to-header mapping is tested in the rspamd package;
// what matters here is whether the headers reach the delivered message.
type fakeSpamChecker struct {
	headers map[string]string
	action  spamcheck.Action
	err     error
}

func (f *fakeSpamChecker) Name() string { return "fake" }
func (f *fakeSpamChecker) Close() error { return nil }

func (f *fakeSpamChecker) Check(_ context.Context, message io.Reader, _ spamcheck.CheckOptions) (*spamcheck.CheckResult, error) {
	// A real checker consumes the message; the session relies on that to fill
	// its temp buffer via the TeeReader.
	if _, err := io.Copy(io.Discard, message); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return &spamcheck.CheckResult{
		CheckerName: "fake",
		Action:      f.action,
		Score:       12.8,
		IsSpam:      true,
		Headers:     f.headers,
	}, nil
}

func flaggedHeaders() map[string]string {
	return map[string]string{
		"X-Spam-Flag":    "YES",
		"X-Spam-Value":   "9",
		"X-Spam-Score":   "12.80",
		"X-Spam-Status":  "Yes, score=12.80 required=15.00",
		"X-Spam-Checker": "rspamd",
	}
}

// newSpamStampingSession builds a session whose local deliveries land in the
// mock, with a single spam checker configured -- the ordinary deployment, and
// the case where add_headers used to be unreachable.
func newSpamStampingSession(t *testing.T, mock *combinedMockServer, checker spamcheck.Checker, addHeaders bool) *Session {
	t.Helper()
	agent := startCombinedMockServer(t, mock)
	backend := &Backend{
		hostname:    "mail.infodancer.net",
		smDelivery:  agent,
		logger:      slog.Default(),
		tempDir:     t.TempDir(),
		spamChecker: checker,
		spamConfig: config.SpamCheckConfig{
			Enabled:    true,
			Checkers:   []config.SpamCheckerConfig{{Type: "rspamd", URL: "http://unused"}},
			AddHeaders: addHeaders,
			FailMode:   config.SpamCheckFailOpen,
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

// TestData_StampsSpamHeaders is the end-to-end case for issue #241: a flagged
// message that is not rejected must carry the verdict, because a Sieve script
// has no other way to see it.
func TestData_StampsSpamHeaders(t *testing.T) {
	mock := &combinedMockServer{}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		headers: flaggedHeaders(),
		action:  spamcheck.ActionFlag,
	}, true)

	if err := s.Data(strings.NewReader("From: sender@external.com\r\nSubject: hello\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Data: %v", err)
	}

	body := deliveredBody(t, mock)
	for _, want := range []string{
		"X-Spam-Flag: YES\r\n",
		"X-Spam-Value: 9\r\n",
		"X-Spam-Score: 12.80\r\n",
		"X-Spam-Status: Yes, score=12.80 required=15.00\r\n",
		"X-Spam-Checker: rspamd\r\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("delivered message is missing %q:\n%s", want, body)
		}
	}

	// The headers must precede the message's own, so a script reading the
	// topmost field gets ours.
	flagIdx := strings.Index(body, "X-Spam-Flag:")
	fromIdx := strings.Index(body, "From: sender@external.com")
	if flagIdx < 0 || fromIdx < 0 || flagIdx > fromIdx {
		t.Errorf("headers were not prepended (flag=%d from=%d):\n%s", flagIdx, fromIdx, body)
	}
}

// TestData_NoSpamHeadersWhenDisabled: add_headers is off by default, and off
// must mean nothing is stamped.
func TestData_NoSpamHeadersWhenDisabled(t *testing.T) {
	mock := &combinedMockServer{}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		headers: flaggedHeaders(),
		action:  spamcheck.ActionFlag,
	}, false)

	if err := s.Data(strings.NewReader("Subject: hello\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Data: %v", err)
	}

	if body := deliveredBody(t, mock); strings.Contains(body, "X-Spam-") {
		t.Errorf("stamped spam headers with add_headers disabled:\n%s", body)
	}
}

// TestData_NoSpamHeadersWhenCheckFailed is the fail-open case: the check did not
// produce a verdict, so none is asserted. Stamping X-Spam-Flag: NO here would
// claim the message was examined and came back clean, which is the same trap
// buildAuthResults avoids by returning "" when it has nothing to report.
func TestData_NoSpamHeadersWhenCheckFailed(t *testing.T) {
	mock := &combinedMockServer{}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		err: io.ErrUnexpectedEOF,
	}, true)

	if err := s.Data(strings.NewReader("Subject: hello\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Data: %v", err)
	}

	if body := deliveredBody(t, mock); strings.Contains(body, "X-Spam-") {
		t.Errorf("stamped a verdict for a check that never completed:\n%s", body)
	}
}

// TestData_KeepsInboundSpamHeaders pins the deliberate decision not to strip.
// An inbound message may carry its own X-Spam-* -- forged by the sender, or set
// by an upstream filter we sit behind -- and it is left alone. Ours goes above
// it, so a reader taking the topmost field gets our verdict.
//
// This is why these headers are advisory only: a client-side rule matching any
// field with that name can still see the sender's claim. Rewriting a message we
// are about to store to close that would interact badly with ARC, S/MIME and
// PGP protected-headers, and would paper over the forgeability rather than fix
// it. The out-of-band verdict on the delivery channel is the fix.
func TestData_KeepsInboundSpamHeaders(t *testing.T) {
	mock := &combinedMockServer{}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		headers: flaggedHeaders(),
		action:  spamcheck.ActionFlag,
	}, true)

	msg := "From: attacker@evil.example\r\n" +
		"X-Spam-Flag: NO\r\n" +
		"X-Spam-Status: No, score=-99.00 required=15.00\r\n" +
		"Subject: your account\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	body := deliveredBody(t, mock)
	if !strings.Contains(body, "X-Spam-Flag: NO") {
		t.Errorf("rewrote the stored message by dropping an inbound header:\n%s", body)
	}
	if !strings.Contains(body, "X-Spam-Flag: YES") {
		t.Errorf("our own verdict is missing:\n%s", body)
	}

	// Ours must be the topmost of the two.
	ours := strings.Index(body, "X-Spam-Flag: YES")
	theirs := strings.Index(body, "X-Spam-Flag: NO")
	if ours < 0 || theirs < 0 || ours > theirs {
		t.Errorf("our verdict is not above the inbound one (ours=%d theirs=%d):\n%s", ours, theirs, body)
	}
}

// TestData_KeepsUpstreamSpamHeadersWhenNotStamping: with stamping off nothing of
// ours is added either, so an upstream filter's headers pass through untouched.
func TestData_KeepsUpstreamSpamHeadersWhenNotStamping(t *testing.T) {
	mock := &combinedMockServer{}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		headers: flaggedHeaders(),
		action:  spamcheck.ActionFlag,
	}, false)

	msg := "X-Spam-Flag: YES\r\nSubject: hello\r\n\r\nbody\r\n"
	if err := s.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	if body := deliveredBody(t, mock); !strings.Contains(body, "X-Spam-Flag: YES") {
		t.Errorf("removed an upstream header while not stamping our own:\n%s", body)
	}
}

// TestData_NoSpamHeadersOnOutboundRelay: our filtering verdicts are ours, and
// disclosing them to the receiving ADMD tells a spammer exactly how their
// message scored. Same reasoning as Authentication-Results on relay.
func TestData_NoSpamHeadersOnOutboundRelay(t *testing.T) {
	mock := &combinedMockServer{validateLocal: map[string]bool{"remote@elsewhere.example": false}}
	s := newSpamStampingSession(t, mock, &fakeSpamChecker{
		headers: flaggedHeaders(),
		action:  spamcheck.ActionFlag,
	}, true)
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
	if body := mock.enqueues[0].body; strings.Contains(body, "X-Spam-") {
		t.Errorf("disclosed our spam verdict on a relayed message:\n%s", body)
	}
}
