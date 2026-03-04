package queue

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
	}
}

// TestWriteCreatesFiles verifies that Write produces one body file and one
// envelope file per recipient, all in the correct directory layout.
func TestWriteCreatesFiles(t *testing.T) {
	cfg := testConfig(t)
	from := "alice@example.com"
	recipients := []string{"bob@gmail.com", "carol@yahoo.com"}
	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\n\r\nHello\r\n")

	if err := Write(cfg, from, recipients, body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Body must exist under msg/com/example/{msgidHex} (hex only, no @domain).
	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body file, got %d: %v", len(bodies), bodies)
	}
	msgidHex := bodies[0]

	// Body filename must be hex-only (no "@").
	if strings.HasPrefix(msgidHex, "tmp_") {
		t.Fatalf("body file is a tmp_ file: %s", msgidHex)
	}
	if strings.Contains(msgidHex, "@") {
		t.Fatalf("body filename contains '@', should be hex only: %s", msgidHex)
	}

	// Full msgid uses sender domain (alice@example.com → example.com), not cfg.Hostname.
	wantMsgID := msgidHex + "@example.com"

	// Body content must include the injected Message-ID header.
	bodyContent, err := os.ReadFile(filepath.Join(msgDir, msgidHex))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	wantHeader := "Message-ID: <" + wantMsgID + ">"
	if !strings.Contains(string(bodyContent), wantHeader) {
		t.Errorf("body missing Message-ID header %q; got:\n%s", wantHeader, bodyContent)
	}

	// One envelope per recipient.
	for _, rcpt := range recipients {
		rcptLocal, rcptDomain := splitAddress(rcpt)
		rcptTLD, rcptSLD := splitDomainLabels(rcptDomain)
		envDir := filepath.Join(cfg.Dir, "env", rcptTLD, rcptSLD)
		envFiles := readDir(t, envDir)

		// Envelope filename uses hex part only: localpart@hex.n
		var found string
		for _, name := range envFiles {
			if strings.HasPrefix(name, rcptLocal+"@"+msgidHex) {
				found = name
				break
			}
		}
		if found == "" {
			t.Errorf("no envelope found for %s in %s; files: %v", rcpt, envDir, envFiles)
			continue
		}

		// Parse and validate envelope content.
		envContent, err := os.ReadFile(filepath.Join(envDir, found))
		if err != nil {
			t.Fatalf("read envelope %s: %v", found, err)
		}
		env := string(envContent)
		// MSGID field must be full RFC 5322 form: hex@hostname
		checkEnvelopeField(t, env, "MSGID", wantMsgID)
		checkEnvelopeField(t, env, "RECIPIENT", rcpt)

		wantSender := "bounces+" + rcptLocal + "=" + rcptDomain + "@mail.example.com"
		checkEnvelopeField(t, env, "SENDER", wantSender)

		// TTL must parse as a future RFC3339 timestamp.
		ttlLine := extractField(env, "TTL")
		ttl, err := time.Parse(time.RFC3339, ttlLine)
		if err != nil {
			t.Errorf("TTL %q not valid RFC3339: %v", ttlLine, err)
		}
		if !ttl.After(time.Now()) {
			t.Errorf("TTL %v is not in the future", ttl)
		}
	}
}

// TestNoTmpFilesAfterWrite verifies no tmp_ files remain after a successful write.
func TestNoTmpFilesAfterWrite(t *testing.T) {
	cfg := testConfig(t)
	body := strings.NewReader("Subject: test\r\n\r\nbody\r\n")

	if err := Write(cfg, "sender@example.com", []string{"rcpt@gmail.com"}, body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Walk the entire queue dir; no tmp_ files should remain.
	err := filepath.Walk(cfg.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasPrefix(info.Name(), "tmp_") {
			t.Errorf("tmp_ file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAtomicBodyWriteFailLeaveNoEnvelope simulates a failure that aborts
// after the body is written but before any envelope. The body tmp_ file
// disappears on cleanup, and no envelope files are created.
//
// We test the easier invariant: if Write returns an error, no envelope
// files matching the pattern localpart@msgid.n exist.
func TestBodyWriteFailLeavesNoEnvelope(t *testing.T) {
	cfg := testConfig(t)

	// Use an io.Reader that always errors to simulate a disk-full mid-stream.
	errReader := &errAfterNReader{n: 0, err: io.ErrUnexpectedEOF}

	err := Write(cfg, "sender@example.com", []string{"rcpt@gmail.com"}, errReader)
	if err == nil {
		t.Fatal("expected Write to fail, got nil")
	}

	// No envelope files should exist.
	envDir := filepath.Join(cfg.Dir, "env")
	if _, err := os.Stat(envDir); os.IsNotExist(err) {
		return // env dir not created — pass
	}
	_ = filepath.Walk(envDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasPrefix(info.Name(), "tmp_") {
			t.Errorf("envelope file present despite body write failure: %s", path)
		}
		return nil
	})
}

// TestVERPFormat checks the VERP address format directly.
func TestVERPFormat(t *testing.T) {
	got := verpAddress("alice@example.com", "bob@gmail.com", "mail.example.com")
	want := "bounces+bob=gmail.com@mail.example.com"
	if got != want {
		t.Errorf("VERP: got %q, want %q", got, want)
	}
}

// TestSplitDomainLabels covers single-label and multi-label domains.
func TestSplitDomainLabels(t *testing.T) {
	cases := []struct{ domain, wantTLD, wantSLD string }{
		{"example.com", "com", "example"},
		{"mail.example.com", "com", "example"},
		{"localhost", "unknown", "localhost"},
	}
	for _, c := range cases {
		tld, sld := splitDomainLabels(c.domain)
		if tld != c.wantTLD || sld != c.wantSLD {
			t.Errorf("splitDomainLabels(%q) = (%q,%q), want (%q,%q)",
				c.domain, tld, sld, c.wantTLD, c.wantSLD)
		}
	}
}

// --- helpers ---

func readDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func checkEnvelopeField(t *testing.T, content, key, wantVal string) {
	t.Helper()
	val := extractField(content, key)
	if val != wantVal {
		t.Errorf("envelope field %s: got %q, want %q", key, val, wantVal)
	}
}

func extractField(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, key+" ") {
			return strings.TrimPrefix(line, key+" ")
		}
	}
	return ""
}

type errAfterNReader struct {
	n   int
	err error
}

func (r *errAfterNReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	r.n -= len(p)
	return len(p), nil
}
