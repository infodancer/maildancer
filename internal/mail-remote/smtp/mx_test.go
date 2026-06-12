package smtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "gmail.com", bodyPath, []*envelope.Envelope{env}, 0)

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
		[]*envelope.Envelope{env1, env2}, 0)

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
		[]*envelope.Envelope{env}, 0)

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
		[]*envelope.Envelope{env}, 0)

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
		[]*envelope.Envelope{env}, 0)

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
		[]*envelope.Envelope{env}, 0)

	err := results[env.Path]
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsPermanent(err) {
		t.Errorf("550 should be permanent, got: %v", err)
	}
}

// --- scripted server for mid-session failure simulation ---

// scriptedServer is a minimal raw SMTP server that accepts deliveries until
// acceptN have completed, then fails according to mode:
//
//	"dropAtMAIL":    close the connection when the next MAIL FROM arrives
//	                 (pre-DATA failure; envelopes are safe to fail over)
//	"dropAfterData": consume the next DATA payload and terminator, then close
//	                 without sending the final 250 (ambiguous outcome)
type scriptedServer struct {
	mode     string
	acceptN  int
	mu       sync.Mutex
	accepted []string // recipients whose DATA got a 250
}

func (s *scriptedServer) acceptedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accepted)
}

func startScriptedServer(t *testing.T, mode string, acceptN int) (string, *scriptedServer) {
	t.Helper()
	s := &scriptedServer{mode: mode, acceptN: acceptN}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return ln.Addr().String(), s
}

func (s *scriptedServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	fmt.Fprintf(conn, "220 scripted ESMTP\r\n")
	delivered := 0
	rcpt := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			fmt.Fprintf(conn, "250 scripted\r\n")
		case strings.HasPrefix(cmd, "MAIL"):
			if s.mode == "dropAtMAIL" && delivered >= s.acceptN {
				return // slam the connection shut
			}
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT"):
			rcpt = strings.TrimSpace(line)
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "DATA"):
			fmt.Fprintf(conn, "354 go\r\n")
			// Consume until the CRLF.CRLF terminator.
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
			}
			if s.mode == "dropAfterData" && delivered >= s.acceptN {
				return // terminator consumed, verdict withheld
			}
			s.mu.Lock()
			s.accepted = append(s.accepted, rcpt)
			s.mu.Unlock()
			delivered++
			fmt.Fprintf(conn, "250 accepted\r\n")
		case strings.HasPrefix(cmd, "RSET"):
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 bye\r\n")
			return
		default:
			fmt.Fprintf(conn, "500 what\r\n")
		}
	}
}

// overrideDialMXSequence makes DialMX dial addrs[i] on the i-th call
// (clamping to the last entry) and returns a counter of calls made.
func overrideDialMXSequence(t *testing.T, addrs ...string) *int {
	t.Helper()
	calls := 0
	orig := DialMX
	DialMX = func(_, _ string) (*gosmtp.Client, error) {
		i := calls
		if i >= len(addrs) {
			i = len(addrs) - 1
		}
		calls++
		return gosmtp.Dial(addrs[i])
	}
	t.Cleanup(func() { DialMX = orig })
	return &calls
}

// --- mid-session failover tests (issue #44) ---

func TestDeliverViaMX_FailoverAfterConnectionDrop(t *testing.T) {
	scriptedAddr, scripted := startScriptedServer(t, "dropAtMAIL", 1)
	realAddr, be, stop := startTestServer(t)
	defer stop()
	calls := overrideDialMXSequence(t, scriptedAddr, realAddr)

	resolver := &fakeResolver{mxRecords: []*net.MX{
		{Host: "mx1.example.com.", Pref: 10},
		{Host: "mx2.example.com.", Pref: 20},
	}}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: t\r\n\r\nfailover\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env1 := makeEnvFile(t, dir, "a@m.0", "b+a=example.com@mail.example.com", "a@example.com", "m@example.com")
	env2 := makeEnvFile(t, dir, "b@m.1", "b+b=example.com@mail.example.com", "b@example.com", "m@example.com")
	env3 := makeEnvFile(t, dir, "c@m.2", "b+c=example.com@mail.example.com", "c@example.com", "m@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "example.com", bodyPath,
		[]*envelope.Envelope{env1, env2, env3}, 0)

	// env1 was accepted by the first host before it died.
	if err := results[env1.Path]; err != nil {
		t.Errorf("env1: expected success on first host, got: %v", err)
	}
	// env2 and env3 failed over to the second host.
	if err := results[env2.Path]; err != nil {
		t.Errorf("env2: expected success via failover, got: %v", err)
	}
	if err := results[env3.Path]; err != nil {
		t.Errorf("env3: expected success via failover, got: %v", err)
	}

	if got := scripted.acceptedCount(); got != 1 {
		t.Errorf("scripted server accepted %d deliveries, want 1", got)
	}
	be.mu.Lock()
	gotReal := len(be.deliveries)
	be.mu.Unlock()
	if gotReal != 2 {
		t.Errorf("second host received %d deliveries, want 2", gotReal)
	}
	if *calls != 2 {
		t.Errorf("dial calls = %d, want 2", *calls)
	}
}

func TestDeliverViaMX_AmbiguousDataDeferredNotRetried(t *testing.T) {
	// First host consumes env1's DATA terminator then dies without a verdict:
	// the message may have been delivered, so env1 must NOT be re-sent on the
	// next host -- it defers to the queue retry. env2 fails over normally.
	scriptedAddr, _ := startScriptedServer(t, "dropAfterData", 0)
	realAddr, be, stop := startTestServer(t)
	defer stop()
	calls := overrideDialMXSequence(t, scriptedAddr, realAddr)

	resolver := &fakeResolver{mxRecords: []*net.MX{
		{Host: "mx1.example.com.", Pref: 10},
		{Host: "mx2.example.com.", Pref: 20},
	}}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: t\r\n\r\nambiguous\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env1 := makeEnvFile(t, dir, "a@m.0", "b+a=example.com@mail.example.com", "a@example.com", "m@example.com")
	env2 := makeEnvFile(t, dir, "b@m.1", "b+b=example.com@mail.example.com", "b@example.com", "m@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "example.com", bodyPath,
		[]*envelope.Envelope{env1, env2}, 0)

	// env1: temporary error (queue retries it later), never permanent.
	err1 := results[env1.Path]
	if err1 == nil {
		t.Fatal("env1: expected error for ambiguous outcome, got success")
	}
	if IsPermanent(err1) {
		t.Errorf("env1: ambiguous outcome must be temporary, got permanent: %v", err1)
	}
	// env2: delivered via the second host.
	if err := results[env2.Path]; err != nil {
		t.Errorf("env2: expected success via failover, got: %v", err)
	}

	// The second host must have received ONLY env2 -- re-sending env1 would
	// risk duplicate delivery.
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.deliveries) != 1 {
		t.Fatalf("second host received %d deliveries, want 1 (env2 only)", len(be.deliveries))
	}
	if got := be.deliveries[0].recipients[0]; got != "b@example.com" {
		t.Errorf("second host received %q, want b@example.com (env2)", got)
	}
	if *calls != 2 {
		t.Errorf("dial calls = %d, want 2", *calls)
	}
}

func TestDeliverViaMX_TempVerdictDoesNotFailOver(t *testing.T) {
	// A 4xx per-recipient verdict is the server's answer, not a connection
	// failure -- it must not trigger a try on the next MX host.
	addr, be, stop := startTestServer(t)
	defer stop()
	be.rejectRcpt = func(to string) error {
		if to == "greylisted@example.com" {
			return &gosmtp.SMTPError{Code: 450, Message: "greylisted, try later"}
		}
		return nil
	}
	calls := overrideDialMXSequence(t, addr)

	resolver := &fakeResolver{mxRecords: []*net.MX{
		{Host: "mx1.example.com.", Pref: 10},
		{Host: "mx2.example.com.", Pref: 20},
	}}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("Subject: t\r\n\r\nverdict\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env1 := makeEnvFile(t, dir, "a@m.0", "b+a=example.com@mail.example.com", "greylisted@example.com", "m@example.com")
	env2 := makeEnvFile(t, dir, "b@m.1", "b+b=example.com@mail.example.com", "ok@example.com", "m@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "example.com", bodyPath,
		[]*envelope.Envelope{env1, env2}, 0)

	err1 := results[env1.Path]
	if err1 == nil || IsPermanent(err1) {
		t.Errorf("env1: want temporary error, got: %v", err1)
	}
	if err := results[env2.Path]; err != nil {
		t.Errorf("env2: expected success on same connection, got: %v", err)
	}
	if *calls != 1 {
		t.Errorf("dial calls = %d, want 1 (no failover on verdicts)", *calls)
	}
}

func TestDeliverViaMX_ConnectionAttemptCap(t *testing.T) {
	calls := 0
	orig := DialMX
	DialMX = func(_, _ string) (*gosmtp.Client, error) {
		calls++
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("refused")}
	}
	t.Cleanup(func() { DialMX = orig })

	// More MX hosts than the attempt cap allows.
	var mxs []*net.MX
	for i := 0; i < 8; i++ {
		mxs = append(mxs, &net.MX{Host: fmt.Sprintf("mx%d.example.com.", i), Pref: uint16(i)})
	}
	resolver := &fakeResolver{mxRecords: mxs}

	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}
	env := makeEnvFile(t, dir, "a@m.0", "b+a=example.com@mail.example.com", "a@example.com", "m@example.com")

	results := DeliverViaMX(context.Background(), resolver, "mail.example.com", "example.com", bodyPath,
		[]*envelope.Envelope{env}, 0)

	if err := results[env.Path]; err == nil || IsPermanent(err) {
		t.Errorf("want temporary error after exhausting hosts, got: %v", err)
	}
	if calls != maxMXAttempts {
		t.Errorf("dial calls = %d, want %d (capped)", calls, maxMXAttempts)
	}
}
