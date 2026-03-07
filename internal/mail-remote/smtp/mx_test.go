package smtp

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
)

// fakeResolver returns pre-configured MX results.
type fakeResolver struct {
	mxRecords []*net.MX
	mxErr     error
	hostAddrs []string
	hostErr   error
}

func (f *fakeResolver) LookupMX(_ string) ([]*net.MX, error) {
	return f.mxRecords, f.mxErr
}

func (f *fakeResolver) LookupHost(_ string) ([]string, error) {
	return f.hostAddrs, f.hostErr
}

// overrideDialMX replaces DialMX with a plain (no-TLS) dialer that
// connects to the given address regardless of the requested addr.
// Restores the original on test cleanup.
func overrideDialMX(t *testing.T, targetAddr string) {
	t.Helper()
	orig := DialMX
	DialMX = func(_, _ string) (*gosmtp.Client, error) {
		return gosmtp.Dial(targetAddr)
	}
	t.Cleanup(func() { DialMX = orig })
}

func TestDeliverViaMX_Success(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialMX(t, addr)

	resolver := &fakeResolver{
		mxRecords: []*net.MX{{Host: "mx.gmail.com.", Pref: 10}},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello via MX\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=gmail.com@mail.example.com",
		"alice@gmail.com",
		"abc123@example.com",
	)

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "gmail.com", bodyPath, []*envelope.Envelope{env})

	if err := results[env.Path]; err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(be.deliveries))
	}
	if !strings.Contains(be.deliveries[0].body, "Hello via MX") {
		t.Errorf("body missing expected content")
	}
}

func TestDeliverViaMX_MultipleEnvelopes(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialMX(t, addr)

	resolver := &fakeResolver{
		mxRecords: []*net.MX{{Host: "mx.gmail.com.", Pref: 10}},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: batch\r\n\r\nbody\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env1 := makeEnvFile(t, dir, "alice@dead1234.0",
		"bounces+alice=gmail.com@mail.example.com", "alice@gmail.com", "dead1234@example.com")
	env2 := makeEnvFile(t, dir, "bob@dead1234.1",
		"bounces+bob=gmail.com@mail.example.com", "bob@gmail.com", "dead1234@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "gmail.com", bodyPath,
		[]*envelope.Envelope{env1, env2})

	for _, env := range []*envelope.Envelope{env1, env2} {
		if err := results[env.Path]; err != nil {
			t.Errorf("envelope %s: expected success, got: %v", env.Path, err)
		}
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 2 {
		t.Fatalf("expected 2 deliveries (VERP), got %d", len(be.deliveries))
	}
}

func TestDeliverViaMX_NullMX(t *testing.T) {
	resolver := &fakeResolver{
		mxRecords: []*net.MX{{Host: ".", Pref: 0}},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=noemail.com@mail.example.com", "alice@noemail.com", "abc123@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "noemail.com", bodyPath,
		[]*envelope.Envelope{env})

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error for null MX")
	}
	if !IsPermanent(err) {
		t.Errorf("null MX should be permanent error, got: %v", err)
	}
}

func TestDeliverViaMX_NoRecords(t *testing.T) {
	resolver := &fakeResolver{
		mxErr:   &net.DNSError{Err: "no such host", IsNotFound: true},
		hostErr: &net.DNSError{Err: "no such host", IsNotFound: true},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=bad.com@mail.example.com", "alice@bad.com", "abc123@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "bad.com", bodyPath,
		[]*envelope.Envelope{env})

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error for no DNS records")
	}
	if !IsPermanent(err) {
		t.Errorf("no records should be permanent error, got: %v", err)
	}
}

func TestDeliverViaMX_FallbackToSecondMX(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()

	// First MX fails to connect, second succeeds.
	callCount := 0
	orig := DialMX
	DialMX = func(dialAddr, hostname string) (*gosmtp.Client, error) {
		callCount++
		if callCount == 1 {
			// Simulate first MX unreachable.
			return nil, &net.OpError{Op: "dial", Err: &net.DNSError{Err: "connection refused"}}
		}
		return gosmtp.Dial(addr)
	}
	t.Cleanup(func() { DialMX = orig })

	resolver := &fakeResolver{
		mxRecords: []*net.MX{
			{Host: "mx1.gmail.com.", Pref: 10},
			{Host: "mx2.gmail.com.", Pref: 20},
		},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nfallback\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "alice@abc123.0",
		"bounces+alice=gmail.com@mail.example.com", "alice@gmail.com", "abc123@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "gmail.com", bodyPath,
		[]*envelope.Envelope{env})

	if err := results[env.Path]; err != nil {
		t.Fatalf("expected success via fallback MX, got: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(be.deliveries))
	}
	if callCount != 2 {
		t.Errorf("expected 2 dial attempts (first fails, second succeeds), got %d", callCount)
	}
}

func TestDeliverViaMX_PermanentRcptFailure(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()
	overrideDialMX(t, addr)

	be.rejectRcpt = func(_ string) error {
		return &gosmtp.SMTPError{Code: 550, Message: "User unknown"}
	}

	resolver := &fakeResolver{
		mxRecords: []*net.MX{{Host: "mx.example.com.", Pref: 10}},
	}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: test\r\n\r\nHello\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := makeEnvFile(t, dir, "nobody@abc123.0",
		"bounces+nobody=example.com@mail.example.com", "nobody@example.com", "abc123@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "example.com", bodyPath,
		[]*envelope.Envelope{env})

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsPermanent(err) {
		t.Errorf("550 should be permanent, got: %v", err)
	}
}
