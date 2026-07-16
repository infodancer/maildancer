package queue

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
	}
}

func TestWriteCreatesFiles(t *testing.T) {
	cfg := testConfig(t)
	from := "alice@example.com"
	recipients := []string{"bob@gmail.com", "carol@yahoo.com"}
	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\n\r\nHello\r\n")

	msgid, err := Write(cfg, from, recipients, "", body)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if msgid == "" {
		t.Fatal("Write returned empty msgid")
	}

	// Body must exist under msg/com/example/{msgidHex}.
	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body file, got %d: %v", len(bodies), bodies)
	}
	msgidHex := bodies[0]

	if strings.HasPrefix(msgidHex, "tmp_") {
		t.Fatalf("body file is a tmp_ file: %s", msgidHex)
	}
	if strings.Contains(msgidHex, "@") {
		t.Fatalf("body filename contains '@': %s", msgidHex)
	}

	wantMsgID := msgidHex + "@example.com"
	if msgid != wantMsgID {
		t.Errorf("returned msgid %q, want %q", msgid, wantMsgID)
	}

	// Body content must include the injected Message-ID header.
	bodyContent, err := os.ReadFile(filepath.Join(msgDir, msgidHex))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	wantHeader := "Message-ID: <" + wantMsgID + ">"
	if !strings.Contains(string(bodyContent), wantHeader) {
		t.Errorf("body missing Message-ID header %q", wantHeader)
	}

	// One envelope per recipient.
	for _, rcpt := range recipients {
		rcptLocal, rcptDomain := splitAddress(rcpt)
		rcptTLD, rcptSLD := splitDomainLabels(rcptDomain)
		envDir := filepath.Join(cfg.Dir, "env", rcptTLD, rcptSLD)
		envFiles := readDir(t, envDir)

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

		envContent, err := os.ReadFile(filepath.Join(envDir, found))
		if err != nil {
			t.Fatalf("read envelope %s: %v", found, err)
		}
		var env queueEnvelope
		if err := json.Unmarshal(envContent, &env); err != nil {
			t.Fatalf("unmarshal envelope %s: %v", found, err)
		}
		if env.MsgID != wantMsgID {
			t.Errorf("envelope MsgID: got %q, want %q", env.MsgID, wantMsgID)
		}
		if env.Recipient != rcpt {
			t.Errorf("envelope Recipient: got %q, want %q", env.Recipient, rcpt)
		}
		wantSender := "bounces+" + rcptLocal + "=" + rcptDomain + "@mail.example.com"
		if env.Sender != wantSender {
			t.Errorf("envelope Sender: got %q, want %q", env.Sender, wantSender)
		}
		if env.Origin != from {
			t.Errorf("envelope Origin: got %q, want %q", env.Origin, from)
		}
		if env.TTL.Before(time.Now()) {
			t.Errorf("TTL %v is not in the future", env.TTL)
		}
		if env.Created.IsZero() {
			t.Error("Created should not be zero")
		}
	}
}

func TestNoTmpFilesAfterWrite(t *testing.T) {
	cfg := testConfig(t)
	body := strings.NewReader("Subject: test\r\n\r\nbody\r\n")

	if _, err := Write(cfg, "sender@example.com", []string{"rcpt@gmail.com"}, "", body); err != nil {
		t.Fatalf("Write: %v", err)
	}

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

func TestBodyWriteFailLeavesNoEnvelope(t *testing.T) {
	cfg := testConfig(t)
	errReader := &errAfterNReader{n: 0, err: io.ErrUnexpectedEOF}

	_, err := Write(cfg, "sender@example.com", []string{"rcpt@gmail.com"}, "", errReader)
	if err == nil {
		t.Fatal("expected Write to fail, got nil")
	}

	envDir := filepath.Join(cfg.Dir, "env")
	if _, err := os.Stat(envDir); os.IsNotExist(err) {
		return
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

func TestWriteValidatesAddresses(t *testing.T) {
	cases := []struct {
		name       string
		from       string
		recipients []string
		wantErr    bool
	}{
		// Traversal in recipient localpart.
		{
			name:       "rcpt localpart path traversal",
			from:       "sender@example.com",
			recipients: []string{"../../etc/passwd@example.com"},
			wantErr:    true,
		},
		// Traversal in recipient domain.
		{
			name:       "rcpt domain path traversal",
			from:       "sender@example.com",
			recipients: []string{"alice@evil/../.."},
			wantErr:    true,
		},
		// Slash in sender domain.
		{
			name:       "sender domain slash",
			from:       "nobody@../escape",
			recipients: []string{"alice@example.com"},
			wantErr:    true,
		},
		// Backslash in recipient localpart.
		{
			name:       "rcpt localpart backslash",
			from:       "sender@example.com",
			recipients: []string{"evil\\path@example.com"},
			wantErr:    true,
		},
		// Normal address: no regression.
		{
			name:       "valid address",
			from:       "alice@example.com",
			recipients: []string{"bob@gmail.com"},
			wantErr:    false,
		},
		// Single-label domain (tld="unknown"): still valid.
		{
			name:       "single-label recipient domain",
			from:       "alice@example.com",
			recipients: []string{"bob@localhost"},
			wantErr:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			parentDir := filepath.Dir(cfg.Dir)

			body := strings.NewReader("Subject: test\r\n\r\nbody\r\n")
			_, err := Write(cfg, tc.from, tc.recipients, "", body)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for from=%q recipients=%v, got nil", tc.from, tc.recipients)
				}
				// For traversal cases, confirm no file escaped the queue dir.
				err := filepath.Walk(parentDir, func(path string, info os.FileInfo, walkErr error) error {
					if walkErr != nil || info.IsDir() {
						return nil
					}
					// Any file directly in parentDir (not inside cfg.Dir) is an escape.
					rel, relErr := filepath.Rel(cfg.Dir, path)
					if relErr != nil {
						return nil
					}
					if strings.HasPrefix(rel, "..") {
						t.Errorf("file escaped queue dir: %s", path)
					}
					return nil
				})
				if err != nil {
					t.Fatalf("walk error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVERPFormat(t *testing.T) {
	got := verpAddress("alice@example.com", "bob@gmail.com", "mail.example.com")
	want := "bounces+bob=gmail.com@mail.example.com"
	if got != want {
		t.Errorf("VERP: got %q, want %q", got, want)
	}
}

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

func TestWriteWithDKIM(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]DKIMKey{
		"example.com": {Selector: "default", Key: priv},
	}

	cfg := Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
		DKIMSign:   NewDKIMSigner(keys),
	}

	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\nSubject: test\r\n\r\nHello\r\n")
	if _, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, "", body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body, got %d", len(bodies))
	}

	content, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(content), "DKIM-Signature:") {
		t.Errorf("body missing DKIM-Signature header")
	}
	if !strings.Contains(string(content), "Message-ID:") {
		t.Errorf("body missing Message-ID header")
	}
	dkimIdx := strings.Index(string(content), "DKIM-Signature:")
	msgidIdx := strings.Index(string(content), "Message-ID:")
	if dkimIdx > msgidIdx {
		t.Errorf("DKIM-Signature should come before Message-ID")
	}
}

func TestWriteWithoutDKIM(t *testing.T) {
	cfg := Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
	}

	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\n\r\nHello\r\n")
	if _, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, "", body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body, got %d", len(bodies))
	}

	content, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(content), "DKIM-Signature:") {
		t.Error("body should not contain DKIM-Signature when signing is disabled")
	}
	if !strings.Contains(string(content), "Message-ID:") {
		t.Error("body missing Message-ID header")
	}
}

func TestSignDKIM_Verifiable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := "From: alice@example.com\r\nTo: bob@gmail.com\r\nSubject: test\r\n\r\nHello\r\n"
	signed, err := SignDKIM("example.com", "sel1", priv, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("SignDKIM: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(signed); err != nil {
		t.Fatal(err)
	}

	b64pub := base64.StdEncoding.EncodeToString(pub)
	txtRecord := "v=DKIM1; k=ed25519; p=" + b64pub

	verifications, err := dkim.VerifyWithOptions(&buf, &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return []string{txtRecord}, nil
		},
	})
	if err != nil {
		t.Fatalf("dkim.Verify: %v", err)
	}
	if len(verifications) == 0 {
		t.Fatal("no DKIM verifications returned")
	}
	for _, v := range verifications {
		if v.Err != nil {
			t.Errorf("DKIM verification failed: %v", v.Err)
		}
	}
}

func TestNewDKIMSigner_NilForEmptyKeys(t *testing.T) {
	signer := NewDKIMSigner(nil)
	if signer != nil {
		t.Error("expected nil signer for nil keys")
	}

	signer = NewDKIMSigner(map[string]DKIMKey{})
	if signer != nil {
		t.Error("expected nil signer for empty map")
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

// TestWriteReusesPresetMsgID verifies that a preset hex id (minted at smtpd
// ingress) is reused verbatim instead of the queue generating its own, so a
// message keeps one id across the inbound->outbound boundary.
func TestWriteReusesPresetMsgID(t *testing.T) {
	cfg := testConfig(t)
	const preset = "0123456789abcdef0123456789abcdef"

	msgid, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, preset,
		strings.NewReader("From: alice@example.com\r\n\r\nHello\r\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if want := preset + "@example.com"; msgid != want {
		t.Errorf("returned msgid %q, want %q", msgid, want)
	}

	// The body file is named by the preset hex, not a freshly-generated one.
	bodies := readDir(t, filepath.Join(cfg.Dir, "msg", "com", "example"))
	if len(bodies) != 1 || bodies[0] != preset {
		t.Fatalf("body files = %v, want exactly [%s]", bodies, preset)
	}
}

// TestWriteRejectsInvalidPresetMsgID verifies a malformed preset id is rejected
// (it would otherwise land in a filesystem path) rather than silently accepted.
func TestWriteRejectsInvalidPresetMsgID(t *testing.T) {
	cfg := testConfig(t)
	for _, bad := range []string{
		"nothex-nothex-nothex-nothex-xxxx",   // 32 chars but not hex
		"abcd",                               // too short
		"0123456789abcdef0123456789abcdef00", // too long
		"../../etc/passwd",                   // path traversal attempt
	} {
		_, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, bad,
			strings.NewReader("body"))
		if err == nil {
			t.Errorf("Write accepted invalid preset msgid %q, want error", bad)
		}
	}
}

// TestWriteOwnerAssignsOwnership verifies that with Owner set, every
// directory level below the queue root and every written file carries the
// requested uid/gid. Run unprivileged this can only chown to the process's
// own ids, but that still exercises the chown calls on every path; the
// root-owned-writer case is covered by the container integration test.
func TestWriteOwnerAssignsOwnership(t *testing.T) {
	cfg := testConfig(t)
	uid, gid := os.Getuid(), os.Getgid()
	cfg.Owner = &Owner{UID: uid, GID: gid}

	body := strings.NewReader("From: alice@example.com\r\n\r\nHello\r\n")
	if _, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, "", body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	checkOwner := func(path string) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Skip("no Stat_t on this platform")
		}
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s owned %d:%d, want %d:%d", path, st.Uid, st.Gid, uid, gid)
		}
	}

	msgDomainDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	envDomainDir := filepath.Join(cfg.Dir, "env", "com", "gmail")
	for _, dir := range []string{
		filepath.Join(cfg.Dir, "msg"),
		filepath.Join(cfg.Dir, "msg", "com"),
		msgDomainDir,
		filepath.Join(cfg.Dir, "env"),
		filepath.Join(cfg.Dir, "env", "com"),
		envDomainDir,
	} {
		checkOwner(dir)
	}
	for _, name := range readDir(t, msgDomainDir) {
		checkOwner(filepath.Join(msgDomainDir, name))
	}
	envs := readDir(t, envDomainDir)
	if len(envs) != 1 {
		t.Fatalf("expected 1 envelope, got %v", envs)
	}
	checkOwner(filepath.Join(envDomainDir, envs[0]))
}

// TestWriteOwnerChownFailureIsAnError verifies a failed chown fails the
// write loudly: silently leaving entries owned by the writing process would
// strand mail the unprivileged queue consumer cannot read.
func TestWriteOwnerChownFailureIsAnError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown to any owner; failure path needs an unprivileged run")
	}
	cfg := testConfig(t)
	cfg.Owner = &Owner{UID: 0, GID: 0}

	body := strings.NewReader("body")
	if _, err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, "", body); err == nil {
		t.Fatal("Write succeeded despite impossible chown, want error")
	}
}
