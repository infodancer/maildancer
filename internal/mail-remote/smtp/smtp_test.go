package smtp

import (
	"context"
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
		srv.Close()
		ln.Close()
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

// makeEnvFile writes an envelope file and returns a parsed *envelope.Envelope.
func makeEnvFile(t *testing.T, dir, filename, sender, recipient, msgid string) *envelope.Envelope {
	t.Helper()
	ttl := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	content := "TTL " + ttl + "\nSENDER " + sender + "\nRECIPIENT " + recipient + "\nMSGID " + msgid + "\n"
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
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
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env})

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
	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env1, env2})

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

	results := DeliverViaSmarthost(context.Background(), sh, bodyPath, []*envelope.Envelope{env})
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
	results := DeliverViaSmarthost(context.Background(), sh, "/nonexistent/body", []*envelope.Envelope{env})
	if results[env.Path] == nil {
		t.Error("expected error for missing body file, got nil")
	}
}
