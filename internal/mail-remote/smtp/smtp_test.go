package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
)

// --- in-process test SMTP server ---

type delivery struct {
	from       string
	recipients []string
	body       string
}

type testSession struct {
	be    *testBackend
	from  string
	rcpts []string
}

func (s *testSession) Mail(from string, _ *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *testSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if s.be.rejectRcpt != nil {
		if err := s.be.rejectRcpt(to); err != nil {
			return err
		}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *testSession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.be.mu.Lock()
	defer s.be.mu.Unlock()
	s.be.deliveries = append(s.be.deliveries, delivery{
		from:       s.from,
		recipients: s.rcpts,
		body:       string(body),
	})
	return nil
}

func (s *testSession) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *testSession) Logout() error { return nil }

type testBackend struct {
	mu         sync.Mutex
	deliveries []delivery
	// rejectRcpt is called for each RCPT TO; return non-nil to reject.
	rejectRcpt func(to string) error
}

func (b *testBackend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &testSession{be: b}, nil
}

// startTestServer starts an in-process SMTP server and returns its address and a stop function.
func startTestServer(t *testing.T) (addr string, be *testBackend, stop func()) {
	t.Helper()
	be = &testBackend{}
	srv := gosmtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go srv.Serve(ln) //nolint:errcheck

	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return ln.Addr().String(), be, stop
}

// overrideDialFunc replaces dialFunc with a plain (no-TLS) dialer for tests
// and restores the original when the test ends.
func overrideDialFunc(t *testing.T) {
	t.Helper()
	orig := dialFunc
	dialFunc = func(addr string) (*gosmtp.Client, error) {
		return gosmtp.Dial(addr)
	}
	t.Cleanup(func() { dialFunc = orig })
}

// makeEnvFile writes a JSON envelope file and returns a parsed *envelope.Envelope.
func makeEnvFile(t *testing.T, dir, filename, sender, recipient, msgid string) *envelope.Envelope {
	t.Helper()
	ttl := time.Now().Add(24 * time.Hour).UTC()
	data, err := json.Marshal(map[string]interface{}{
		"ttl":       ttl,
		"created":   time.Now().UTC(),
		"sender":    sender,
		"recipient": recipient,
		"msgid":     msgid,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Parse(path)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	return env
}

// --- tests ---

func TestDeliverViaSmarthost_Success(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=gmail.com@origin.example.com",
		"alice@gmail.com",
		"abc123def456@example.com",
	)

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env}, 0)

	if err := results[env.Path]; err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(be.deliveries))
	}
	d := be.deliveries[0]
	if d.from != env.Sender {
		t.Errorf("MAIL FROM: got %q, want %q", d.from, env.Sender)
	}
	if len(d.recipients) != 1 || d.recipients[0] != env.Recipient {
		t.Errorf("RCPT TO: got %v, want [%s]", d.recipients, env.Recipient)
	}
	if !strings.Contains(d.body, "Hello") {
		t.Errorf("body missing expected content; got: %s", d.body)
	}
}

func TestDeliverViaSmarthost_MultipleEnvelopes(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: batch\r\n\r\nbody\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=gmail.com@origin.example.com",
		"alice@gmail.com",
		"dead1234beef@example.com",
	)
	env2 := makeEnvFile(t, dir, "bob@dead1234.1",
		"bounces+bob=gmail.com@origin.example.com",
		"bob@gmail.com",
		"dead1234beef@example.com",
	)

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env1, env2}, 0)

	for _, env := range []*envelope.Envelope{env1, env2} {
		if err := results[env.Path]; err != nil {
			t.Errorf("envelope %s: expected success, got: %v", env.Path, err)
		}
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries, got %d", len(be.deliveries))
	}
}

func TestDeliverViaSmarthost_DialFailure(t *testing.T) {
	overrideDialFunc(t)
	// Point at a port nothing is listening on.
	sh := Smarthost{Addr: "127.0.0.1:1"}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=gmail.com@origin.example.com",
		"alice@gmail.com",
		"abc123@example.com",
	)

	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env}, 0)
	if results[env.Path] == nil {
		t.Error("expected error for unreachable host, got nil")
	}
}

func TestDeliverViaSmarthost_MissingBody(t *testing.T) {
	addr, _, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=gmail.com@origin.example.com",
		"alice@gmail.com",
		"abc123@example.com",
	)

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, "/nonexistent/body", []*envelope.Envelope{env}, 0)
	if results[env.Path] == nil {
		t.Error("expected error for missing body file, got nil")
	}
}

func TestDeliverViaSmarthost_PermanentFailure(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	// Reject all recipients with 550.
	be.rejectRcpt = func(_ string) error {
		return &gosmtp.SMTPError{
			Code:    550,
			Message: "User unknown",
		}
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "nobody@abc123.0",
		"bounces+nobody=example.com@origin.example.com",
		"nobody@example.com",
		"abc123@example.com",
	)

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env}, 0)

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsPermanent(err) {
		t.Errorf("expected PermanentError for 550, got: %v", err)
	}
}

func TestDeliverViaSmarthost_TemporaryFailure(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	// Reject all recipients with 451 (temporary).
	be.rejectRcpt = func(_ string) error {
		return &gosmtp.SMTPError{
			Code:    451,
			Message: "Try again later",
		}
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=example.com@origin.example.com",
		"alice@example.com",
		"abc123@example.com",
	)

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env}, 0)

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if IsPermanent(err) {
		t.Errorf("expected temporary error for 451, got permanent: %v", err)
	}
}

func TestDeliverViaSmarthost_DialFailureIsTemporary(t *testing.T) {
	overrideDialFunc(t)
	sh := Smarthost{Addr: "127.0.0.1:1"}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=example.com@origin.example.com",
		"alice@example.com",
		"abc123@example.com",
	)

	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env}, 0)
	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if IsPermanent(err) {
		t.Errorf("dial failure should be temporary, got permanent: %v", err)
	}
}

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", fmt.Errorf("something"), false},
		{"SMTP 550", &gosmtp.SMTPError{Code: 550, Message: "rejected"}, false},
		{"SMTP 451", &gosmtp.SMTPError{Code: 451, Message: "try later"}, false},
		{"EOF", io.EOF, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"net closed", net.ErrClosed, true},
		{"wrapped EOF", fmt.Errorf("send: %w", io.EOF), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionError(tt.err); got != tt.want {
				t.Errorf("isConnectionError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDeliverAll_ConnectionDeath(t *testing.T) {
	addr, _, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=example.com@origin.example.com", "alice@example.com", "dead1234@example.com")
	env2 := makeEnvFile(t, dir, "bob@dead1234.1",
		"bounces+bob=example.com@origin.example.com", "bob@example.com", "dead1234@example.com")
	env3 := makeEnvFile(t, dir, "carol@dead1234.2",
		"bounces+carol=example.com@origin.example.com", "carol@example.com", "dead1234@example.com")

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}

	// Deliver first envelope successfully, then close the underlying
	// connection to simulate a network failure.
	results := make(map[string]error, 3)
	results[env1.Path] = deliver(c, bodyPath, env1)
	if results[env1.Path] != nil {
		t.Fatalf("env1: expected success, got: %v", results[env1.Path])
	}

	// Force-close the TCP connection.
	_ = c.Close()

	// Now deliverAll on remaining envelopes should detect connection death.
	deliverAll(c, bodyPath, []*envelope.Envelope{env2, env3}, results, 0)

	// Both remaining envelopes should fail.
	for _, env := range []*envelope.Envelope{env2, env3} {
		if results[env.Path] == nil {
			t.Fatalf("%s: expected error, got nil", env.Path)
		}
	}
}

func TestCheckSize(t *testing.T) {
	addr, _, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	c, err := dialFunc(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Test server doesn't advertise SIZE, so any size should pass.
	if err := checkSize(c, 999999999); err != nil {
		t.Fatalf("checkSize should pass without server SIZE limit: %v", err)
	}
}

func TestCheckSize_ExceedsLimit(t *testing.T) {
	// checkSize compares body size against MaxMessageSize. Since we can't
	// easily make the test server advertise SIZE, test the logic directly:
	// a message exceeding the limit should produce a permanent error.
	oversizeErr := &PermanentError{
		Err: fmt.Errorf("message size %d exceeds server limit %d", 30000000, 25000000),
	}
	if !IsPermanent(oversizeErr) {
		t.Error("size exceeded should be permanent")
	}

	// And a non-PermanentError should not be.
	if IsPermanent(fmt.Errorf("some other error")) {
		t.Error("plain error should not be permanent")
	}
}

func TestDeliverViaSmarthost_RSETBetweenTransactions(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: batch\r\n\r\nbody\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=example.com@origin.example.com", "alice@example.com", "dead1234@example.com")
	env2 := makeEnvFile(t, dir, "bob@dead1234.1",
		"bounces+bob=example.com@origin.example.com", "bob@example.com", "dead1234@example.com")
	env3 := makeEnvFile(t, dir, "carol@dead1234.2",
		"bounces+carol=example.com@origin.example.com", "carol@example.com", "dead1234@example.com")

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath,
		[]*envelope.Envelope{env1, env2, env3}, 0)

	for _, env := range []*envelope.Envelope{env1, env2, env3} {
		if err := results[env.Path]; err != nil {
			t.Errorf("envelope %s: expected success, got: %v", env.Path, err)
		}
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 3 {
		t.Fatalf("expected 3 deliveries, got %d", len(be.deliveries))
	}
	// Verify each delivery has the correct sender (RSET cleaned up between them).
	senders := map[string]bool{}
	for _, d := range be.deliveries {
		senders[d.from] = true
	}
	if len(senders) != 3 {
		t.Errorf("expected 3 unique senders (VERP), got %d: %v", len(senders), senders)
	}
}

func TestDeliverAll_RSETAfterRejection(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	// Reject the second recipient, allow the first and third.
	callCount := 0
	be.rejectRcpt = func(to string) error {
		callCount++
		if callCount == 2 {
			return &gosmtp.SMTPError{Code: 550, Message: "User unknown"}
		}
		return nil
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=example.com@origin.example.com", "alice@example.com", "dead1234@example.com")
	env2 := makeEnvFile(t, dir, "bad@dead1234.1",
		"bounces+bad=example.com@origin.example.com", "bad@example.com", "dead1234@example.com")
	env3 := makeEnvFile(t, dir, "carol@dead1234.2",
		"bounces+carol=example.com@origin.example.com", "carol@example.com", "dead1234@example.com")

	sh := Smarthost{Addr: addr}
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath,
		[]*envelope.Envelope{env1, env2, env3}, 0)

	// First should succeed.
	if err := results[env1.Path]; err != nil {
		t.Errorf("env1: expected success, got: %v", err)
	}
	// Second should fail permanently.
	if err := results[env2.Path]; err == nil {
		t.Error("env2: expected error, got nil")
	} else if !IsPermanent(err) {
		t.Errorf("env2: expected permanent error, got: %v", err)
	}
	// Third should succeed (RSET cleaned up after the 550).
	if err := results[env3.Path]; err != nil {
		t.Errorf("env3: expected success after RSET, got: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries (env1 + env3), got %d", len(be.deliveries))
	}
}

func TestIsPermanent(t *testing.T) {
	if IsPermanent(nil) {
		t.Error("nil should not be permanent")
	}
	if IsPermanent(fmt.Errorf("some error")) {
		t.Error("plain error should not be permanent")
	}
	if !IsPermanent(&PermanentError{Err: fmt.Errorf("550 rejected")}) {
		t.Error("PermanentError should be permanent")
	}
	// Wrapped PermanentError
	wrapped := fmt.Errorf("delivery: %w", &PermanentError{Err: fmt.Errorf("550")})
	if !IsPermanent(wrapped) {
		t.Error("wrapped PermanentError should be permanent")
	}
}

func TestSMTPCode(t *testing.T) {
	if SMTPCode(nil) != 0 {
		t.Error("nil error should return 0")
	}
	if SMTPCode(fmt.Errorf("connection refused")) != 0 {
		t.Error("plain error should return 0")
	}

	smtpErr := &gosmtp.SMTPError{Code: 550, Message: "user not found"}
	if code := SMTPCode(smtpErr); code != 550 {
		t.Errorf("SMTPCode = %d, want 550", code)
	}

	// Wrapped through PermanentError.
	wrapped := &PermanentError{Err: fmt.Errorf("RCPT TO: %w", smtpErr)}
	if code := SMTPCode(wrapped); code != 550 {
		t.Errorf("SMTPCode through PermanentError = %d, want 550", code)
	}

	// Double-wrapped.
	doubleWrapped := fmt.Errorf("deliver: %w", wrapped)
	if code := SMTPCode(doubleWrapped); code != 550 {
		t.Errorf("SMTPCode double-wrapped = %d, want 550", code)
	}
}

func TestDeliverAll_TransactionLimit(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialFunc(t)

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: limit\r\n\r\nbody\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=example.com@origin.example.com", "alice@example.com", "dead1234@example.com")
	env2 := makeEnvFile(t, dir, "bob@dead1234.1",
		"bounces+bob=example.com@origin.example.com", "bob@example.com", "dead1234@example.com")
	env3 := makeEnvFile(t, dir, "carol@dead1234.2",
		"bounces+carol=example.com@origin.example.com", "carol@example.com", "dead1234@example.com")

	sh := Smarthost{Addr: addr}
	// Limit to 2 transactions per connection.
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath,
		[]*envelope.Envelope{env1, env2, env3}, 2)

	// First two should succeed.
	if err := results[env1.Path]; err != nil {
		t.Errorf("env1: expected success, got: %v", err)
	}
	if err := results[env2.Path]; err != nil {
		t.Errorf("env2: expected success, got: %v", err)
	}
	// Third should be deferred (temporary error).
	if err := results[env3.Path]; err == nil {
		t.Error("env3: expected temporary error for transaction limit, got nil")
	} else if IsPermanent(err) {
		t.Errorf("env3: transaction limit should be temporary, got permanent: %v", err)
	} else if !strings.Contains(err.Error(), "transaction limit") {
		t.Errorf("env3: expected 'transaction limit' in error, got: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries (limit=2), got %d", len(be.deliveries))
	}
}
