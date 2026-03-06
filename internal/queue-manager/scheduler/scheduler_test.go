package scheduler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- extractMsgID ---

func TestExtractMsgID(t *testing.T) {
	cases := []struct {
		name   string
		wantID string
		wantOK bool
	}{
		// Standard form: localpart@hex.n
		{"alice@abc123def456.0", "abc123def456", true},
		{"bob@deadbeef1234.99", "deadbeef1234", true},
		// localpart with dots
		{"first.last@abc123.1", "abc123", true},
		// msgid contains no "@": invalid
		{"abc123def456", "", false},
		// no "." after msgid: invalid
		{"alice@abc123", "", false},
		// .delivering suffix: in-flight, skip
		{"alice@abc123def456.0.delivering", "", false},
		// empty
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := extractMsgID(c.name)
		if ok != c.wantOK || got != c.wantID {
			t.Errorf("extractMsgID(%q) = (%q, %v), want (%q, %v)",
				c.name, got, ok, c.wantID, c.wantOK)
		}
	}
}

// --- isReady ---

func TestIsReady_OldEnough(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "env-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Set mtime to 10 minutes ago — should be ready (zero TTL falls back to 5m minimum).
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(f.Name(), old, old); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if !s.isReady(f.Name(), time.Time{}) {
		t.Error("expected isReady=true for file 10 minutes old")
	}
}

func TestIsReady_TooRecent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "env-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// mtime is effectively now — not ready.
	s := New(Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if s.isReady(f.Name(), time.Time{}) {
		t.Error("expected isReady=false for just-created file")
	}
}

func TestIsReady_MissingFile(t *testing.T) {
	s := New(Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if s.isReady("/nonexistent/path/file", time.Time{}) {
		t.Error("expected isReady=false for missing file")
	}
}

func TestIsReady_BackoffIncreasesWithAge(t *testing.T) {
	dir := t.TempDir()
	msgTTL := 7 * 24 * time.Hour
	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute, MessageTTL: msgTTL})

	// Create an envelope file with mtime 6 minutes ago.
	f, err := os.CreateTemp(dir, "env-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	sixMinAgo := time.Now().Add(-6 * time.Minute)
	if err := os.Chtimes(f.Name(), sixMinAgo, sixMinAgo); err != nil {
		t.Fatal(err)
	}

	// Young message (TTL almost full): base interval ~5m, so 6m since last attempt → ready.
	youngTTL := time.Now().Add(msgTTL - 10*time.Minute)
	if !s.isReady(f.Name(), youngTTL) {
		t.Error("expected isReady=true for young message with 6m since last attempt")
	}

	// Old message (3 hours old): interval ~40m, so 6m since last attempt → not ready.
	oldTTL := time.Now().Add(msgTTL - 3*time.Hour)
	if s.isReady(f.Name(), oldTTL) {
		t.Error("expected isReady=false for 3h-old message with only 6m since last attempt")
	}
}

// --- retryInterval ---

func TestRetryInterval(t *testing.T) {
	cases := []struct {
		age  time.Duration
		want time.Duration
		tol  time.Duration // tolerance for floating-point rounding
	}{
		{0, 5 * time.Minute, time.Second},
		{time.Hour, 10 * time.Minute, time.Second},
		{2 * time.Hour, 20 * time.Minute, time.Second},
		{3 * time.Hour, 40 * time.Minute, time.Second},
		{4 * time.Hour, 80 * time.Minute, time.Second},
		{6 * time.Hour, 4 * time.Hour, 0},  // capped
		{24 * time.Hour, 4 * time.Hour, 0}, // capped
		{-time.Hour, 5 * time.Minute, 0},   // negative age → base
	}
	for _, c := range cases {
		got := retryInterval(c.age)
		diff := got - c.want
		if diff < 0 {
			diff = -diff
		}
		if diff > c.tol {
			t.Errorf("retryInterval(%v) = %v, want %v (±%v)", c.age, got, c.want, c.tol)
		}
	}
}

// Verify the curve is monotonically increasing.
func TestRetryInterval_Monotonic(t *testing.T) {
	prev := retryInterval(0)
	for age := 10 * time.Minute; age <= 24*time.Hour; age += 10 * time.Minute {
		cur := retryInterval(age)
		if cur < prev {
			t.Errorf("retryInterval(%v) = %v < retryInterval(%v) = %v", age, cur, age-10*time.Minute, prev)
		}
		prev = cur
	}
}

// --- resolveBody ---

func TestResolveBody(t *testing.T) {
	dir := t.TempDir()
	msgid := "abc123def456"

	// Create body file at the expected path.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(bodyDir, msgid)
	if err := os.WriteFile(bodyPath, []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	got, err := s.resolveBody("ignored-env-path", msgid)
	if err != nil {
		t.Fatalf("resolveBody: %v", err)
	}
	if got != bodyPath {
		t.Errorf("resolveBody = %q, want %q", got, bodyPath)
	}
}

func TestResolveBody_Missing(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	_, err := s.resolveBody("ignored", "nonexistent123")
	if err == nil {
		t.Error("expected error for missing body")
	}
}

// --- processDomainDir with fake mail-remote ---

// TestProcessDomainDir_InvokesMailRemote creates a minimal queue directory,
// makes envelope files appear ready (old mtime), and verifies that a fake
// mail-remote is invoked with the body and envelope paths.
//
// The fake binary reads QUEUE_MGR_RECORD_FILE from the environment
// (scheduler.go passes os.Environ() to the subprocess) and writes its
// argv to that file.
func TestProcessDomainDir_InvokesMailRemote(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)

	dir := t.TempDir()
	msgid := "deadbeef1234"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Envelope file for alice@gmail.com.
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte("MSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Age the envelope so isReady returns true.
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Set record file path via env var (t.Setenv restores automatically).
	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := New(Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := strings.TrimSpace(string(data))

	if !strings.Contains(args, msgid) {
		t.Errorf("expected args to contain msgid %q; got: %s", msgid, args)
	}
	if !strings.Contains(args, "alice@"+msgid+".0") {
		t.Errorf("expected args to contain envelope filename; got: %s", args)
	}
	if strings.Contains(args, "--final") {
		t.Errorf("expected --final NOT to be passed for non-expired envelope; got: %s", args)
	}
}

// TestProcessDomainDir_SkipsNotReady verifies that envelopes with recent
// mtime are not passed to mail-remote.
func TestProcessDomainDir_SkipsNotReady(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "cafebabe5678"

	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(envDir, "bob@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte("MSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// mtime is now — not ready; no need to chtimes

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := New(Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	if _, err := os.Stat(recordFile); !os.IsNotExist(err) {
		t.Error("expected mail-remote not to be invoked for not-ready envelope")
	}
}

// --- parseTTL ---

func TestParseTTL_Valid(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	ttl := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	content := "TTL " + ttl.Format(time.RFC3339) + "\nSENDER x@y.com\nRECIPIENT a@b.com\nMSGID abc123\n"
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := parseTTL(envPath)
	if err != nil {
		t.Fatalf("parseTTL: %v", err)
	}
	if !got.Equal(ttl) {
		t.Errorf("parseTTL = %v, want %v", got, ttl)
	}
}

func TestParseTTL_Missing(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, []byte("SENDER x@y.com\nRECIPIENT a@b.com\nMSGID abc123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := parseTTL(envPath)
	if err != nil {
		t.Fatalf("parseTTL: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("expected zero time for missing TTL, got %v", got)
	}
}

func TestParseTTL_Invalid(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, []byte("TTL not-a-date\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := parseTTL(envPath)
	if err == nil {
		t.Error("expected error for invalid TTL")
	}
}

// --- expired envelope cleanup ---

func TestProcessDomainDir_ExpiredEnvelopesDeleted(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "expired1234"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	// Expired envelope (TTL in the past).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	expiredTTL := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	envContent := "TTL " + expiredTTL + "\nSENDER bounce@example.com\nRECIPIENT alice@gmail.com\nMSGID " + msgid + "\n"
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	// Age the mtime so isReady is also true.
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := New(Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// mail-remote should have been invoked (final attempt).
	data, readErr := os.ReadFile(recordFile)
	if readErr != nil {
		t.Fatalf("expected mail-remote to be invoked for final delivery attempt: %v", readErr)
	}
	argsStr := string(data)
	if !strings.Contains(argsStr, "--final") {
		t.Errorf("expected --final flag in args; got: %s", argsStr)
	}

	// Envelope should be deleted after final attempt.
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Error("expected expired envelope to be deleted after final attempt")
	}
}

// TestProcessDomainDir_MixedBatch verifies that expired envelopes get
// individual --final invocations while active envelopes are batched without it.
func TestProcessDomainDir_MixedBatch(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "mixed5678"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Expired envelope for alice.
	expiredTTL := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	aliceEnv := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(aliceEnv, []byte("TTL "+expiredTTL+"\nSENDER bounce@example.com\nRECIPIENT alice@gmail.com\nMSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(aliceEnv, old, old); err != nil {
		t.Fatal(err)
	}

	// Active envelope for bob (no TTL → not expired, old mtime → ready).
	bobEnv := filepath.Join(envDir, "bob@"+msgid+".1")
	if err := os.WriteFile(bobEnv, []byte("MSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bobEnv, old, old); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := New(Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	invocations := strings.Split(strings.TrimSpace(string(data)), "---")

	// Should be two separate invocations.
	var finalInvocations, normalInvocations int
	for _, inv := range invocations {
		inv = strings.TrimSpace(inv)
		if inv == "" {
			continue
		}
		if strings.Contains(inv, "--final") {
			finalInvocations++
			// The --final invocation should contain only alice's envelope.
			if !strings.Contains(inv, "alice@"+msgid+".0") {
				t.Errorf("--final invocation missing alice's envelope; got: %s", inv)
			}
			if strings.Contains(inv, "bob@"+msgid+".1") {
				t.Errorf("--final invocation should not contain bob's envelope; got: %s", inv)
			}
		} else {
			normalInvocations++
			// The normal invocation should contain bob's envelope.
			if !strings.Contains(inv, "bob@"+msgid+".1") {
				t.Errorf("normal invocation missing bob's envelope; got: %s", inv)
			}
			if strings.Contains(inv, "alice@"+msgid+".0") {
				t.Errorf("normal invocation should not contain alice's envelope; got: %s", inv)
			}
		}
	}
	if finalInvocations != 1 {
		t.Errorf("expected 1 --final invocation, got %d", finalInvocations)
	}
	if normalInvocations != 1 {
		t.Errorf("expected 1 normal invocation, got %d", normalInvocations)
	}

	// Alice's expired envelope should be deleted.
	if _, err := os.Stat(aliceEnv); !os.IsNotExist(err) {
		t.Error("expected expired envelope (alice) to be deleted")
	}
	// Bob's active envelope should still exist.
	if _, err := os.Stat(bobEnv); os.IsNotExist(err) {
		t.Error("bob's active envelope should NOT be deleted")
	}
}

// --- orphan body cleanup ---

func TestCleanOrphanBodies(t *testing.T) {
	dir := t.TempDir()
	msgid := "orphan5678"

	// Body file with no envelopes.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(bodyDir, msgid)
	if err := os.WriteFile(bodyPath, []byte("orphan body"), 0600); err != nil {
		t.Fatal(err)
	}

	// Empty env dir (no envelopes).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	s.cleanOrphanBodies(envDir)

	if _, err := os.Stat(bodyPath); !os.IsNotExist(err) {
		t.Error("expected orphan body to be deleted")
	}
}

func TestCleanOrphanBodies_PreservesActive(t *testing.T) {
	dir := t.TempDir()
	msgid := "active9876"

	// Body file.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(bodyDir, msgid)
	if err := os.WriteFile(bodyPath, []byte("active body"), 0600); err != nil {
		t.Fatal(err)
	}

	// Envelope still exists.
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte("MSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	s.cleanOrphanBodies(envDir)

	if _, err := os.Stat(bodyPath); os.IsNotExist(err) {
		t.Error("active body should NOT be deleted")
	}
}

// --- RunOnce (empty queue) ---

func TestRunOnce_EmptyQueue(t *testing.T) {
	s := New(Config{
		QueueDir: t.TempDir(),
		Binary:   "mail-remote",
		Interval: time.Minute,
	})
	if err := s.RunOnce(); err != nil {
		t.Fatalf("RunOnce on empty queue: %v", err)
	}
}

// --- claim / unclaim ---

func TestClaimUnclaim(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "alice@abc123.0")
	if err := os.WriteFile(original, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Claim renames to .delivering.
	claimed, err := claim(original)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed != original+deliveringSuffix {
		t.Errorf("claimed = %q, want %q", claimed, original+deliveringSuffix)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Error("original should not exist after claim")
	}
	if _, err := os.Stat(claimed); err != nil {
		t.Error("claimed file should exist")
	}

	// Unclaim renames back.
	restored, err := unclaim(claimed)
	if err != nil {
		t.Fatalf("unclaim: %v", err)
	}
	if restored != original {
		t.Errorf("restored = %q, want %q", restored, original)
	}
	if _, err := os.Stat(original); err != nil {
		t.Error("original should exist after unclaim")
	}
}

func TestClaim_AlreadyClaimed(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "alice@abc123.0")
	if err := os.WriteFile(original, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := claim(original); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// Second claim should fail (original no longer exists).
	if _, err := claim(original); err == nil {
		t.Error("expected error on second claim")
	}
}

func TestClaim_PreservesMtime(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "alice@abc123.0")
	if err := os.WriteFile(original, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(original, old, old); err != nil {
		t.Fatal(err)
	}

	claimed, err := claim(original)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	fi, err := os.Stat(claimed)
	if err != nil {
		t.Fatal(err)
	}
	// Rename preserves mtime on Linux/macOS.
	diff := fi.ModTime().Sub(old)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("mtime changed by %v after claim; expected preserved", diff)
	}
}

// TestProcessDomainDir_ClaimedSkippedByConcurrentScan verifies that
// .delivering files are invisible to a concurrent scan.
func TestProcessDomainDir_ClaimedSkippedByConcurrentScan(t *testing.T) {
	dir := t.TempDir()
	msgid := "concurrent1234"

	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create an envelope already in .delivering state (simulating in-flight).
	claimedFile := filepath.Join(envDir, "alice@"+msgid+".0"+deliveringSuffix)
	if err := os.WriteFile(claimedFile, []byte("MSGID "+msgid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(claimedFile, old, old); err != nil {
		t.Fatal(err)
	}

	fakeBin := buildFakeMailRemote(t)
	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := New(Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	// processDomainDir directly — no recovery pass, simulating concurrent scan.
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// mail-remote should NOT have been invoked.
	if _, err := os.Stat(recordFile); !os.IsNotExist(err) {
		t.Error("expected mail-remote NOT to be invoked for .delivering envelope")
	}

	// The .delivering file should still be there (not our responsibility).
	if _, err := os.Stat(claimedFile); os.IsNotExist(err) {
		t.Error(".delivering file should still exist")
	}
}

func TestRecoverStaleDeliveries(t *testing.T) {
	dir := t.TempDir()

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a stale .delivering file.
	staleOriginal := filepath.Join(envDir, "alice@stale1234.0")
	staleClaimed := staleOriginal + deliveringSuffix
	if err := os.WriteFile(staleClaimed, []byte("MSGID stale1234\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Also a normal envelope that shouldn't be touched.
	normalEnv := filepath.Join(envDir, "bob@normal5678.0")
	if err := os.WriteFile(normalEnv, []byte("MSGID normal5678\n"), 0600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	s.recoverStaleDeliveries(filepath.Join(dir, "env"))

	// Stale .delivering should be renamed back to original.
	if _, err := os.Stat(staleClaimed); !os.IsNotExist(err) {
		t.Error("stale .delivering file should be gone after recovery")
	}
	if _, err := os.Stat(staleOriginal); err != nil {
		t.Error("original envelope should be restored after recovery")
	}

	// Normal envelope untouched.
	if _, err := os.Stat(normalEnv); err != nil {
		t.Error("normal envelope should be untouched")
	}
}

// --- helpers ---

// buildFakeMailRemote compiles a tiny Go program that reads QUEUE_MGR_RECORD_FILE
// from the environment and writes its arguments (one per line) to that file.
func buildFakeMailRemote(t *testing.T) string {
	t.Helper()

	src := `package main

import (
	"os"
	"strings"
)

func main() {
	recordFile := os.Getenv("QUEUE_MGR_RECORD_FILE")
	if recordFile == "" {
		os.Exit(0)
	}
	args := strings.Join(os.Args[1:], "\n") + "\n---\n"
	f, err := os.OpenFile(recordFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(1)
	}
	_, _ = f.WriteString(args)
	_ = f.Close()
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "fake-mail-remote")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake mail-remote: %v", err)
	}
	return binPath
}
