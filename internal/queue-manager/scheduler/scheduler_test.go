package scheduler

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/queue-manager/config"
	"github.com/infodancer/maildancer/internal/queue-manager/delivery"
	"google.golang.org/grpc"
)

// mustNew is a test helper that creates a Scheduler and fails the test on error.
func mustNew(t *testing.T, cfg Config) *Scheduler {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

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
	_ = f.Close()

	// Set mtime to 10 minutes ago -- should be ready (zero TTL falls back to 5m minimum).
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(f.Name(), old, old); err != nil {
		t.Fatal(err)
	}

	s := mustNew(t, Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if !s.isReady(f.Name(), time.Time{}) {
		t.Error("expected isReady=true for file 10 minutes old")
	}
}

func TestIsReady_TooRecent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "env-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// mtime is effectively now -- not ready.
	s := mustNew(t, Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if s.isReady(f.Name(), time.Time{}) {
		t.Error("expected isReady=false for just-created file")
	}
}

func TestIsReady_MissingFile(t *testing.T) {
	s := mustNew(t, Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if s.isReady("/nonexistent/path/file", time.Time{}) {
		t.Error("expected isReady=false for missing file")
	}
}

func TestIsReady_BackoffIncreasesWithAge(t *testing.T) {
	dir := t.TempDir()
	msgTTL := 7 * 24 * time.Hour
	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute, MessageTTL: msgTTL})

	// Create an envelope file with mtime 6 minutes ago.
	f, err := os.CreateTemp(dir, "env-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
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

	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
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
	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
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
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
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

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
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
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	// mtime is now -- not ready; no need to chtimes

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	if _, err := os.Stat(recordFile); !os.IsNotExist(err) {
		t.Error("expected mail-remote not to be invoked for not-ready envelope")
	}
}

// --- parseEnvelope ---

func TestParseEnvelope_Valid(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	ttl := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	content := fmt.Sprintf(`{"ttl":"%s","sender":"x@y.com","recipient":"a@b.com","msgid":"abc123","origin":"user@example.com"}`, ttl.Format(time.RFC3339))
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	env, err := parseEnvelope(envPath)
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if !env.TTL.Equal(ttl) {
		t.Errorf("TTL = %v, want %v", env.TTL, ttl)
	}
	if env.Origin != "user@example.com" {
		t.Errorf("Origin = %q, want %q", env.Origin, "user@example.com")
	}
	if env.Recipient != "a@b.com" {
		t.Errorf("Recipient = %q, want %q", env.Recipient, "a@b.com")
	}
}

func TestParseEnvelope_MissingTTL(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, []byte(`{"sender":"x@y.com","recipient":"a@b.com","msgid":"abc123"}`), 0600); err != nil {
		t.Fatal(err)
	}

	env, err := parseEnvelope(envPath)
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if !env.TTL.IsZero() {
		t.Errorf("expected zero TTL for missing field, got %v", env.TTL)
	}
}

func TestParseEnvelope_Invalid(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, []byte("not valid json"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := parseEnvelope(envPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
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
	envContent := fmt.Sprintf(`{"ttl":"%s","sender":"bounce@example.com","recipient":"alice@gmail.com","msgid":"%s"}`, expiredTTL, msgid)
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

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
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
	if err := os.WriteFile(aliceEnv, []byte(fmt.Sprintf(`{"ttl":"%s","sender":"bounce@example.com","recipient":"alice@gmail.com","msgid":"%s"}`, expiredTTL, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(aliceEnv, old, old); err != nil {
		t.Fatal(err)
	}

	// Active envelope for bob (no TTL → not expired, old mtime → ready).
	bobEnv := filepath.Join(envDir, "bob@"+msgid+".1")
	if err := os.WriteFile(bobEnv, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bobEnv, old, old); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
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

	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
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
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}

	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
	s.cleanOrphanBodies(envDir)

	if _, err := os.Stat(bodyPath); os.IsNotExist(err) {
		t.Error("active body should NOT be deleted")
	}
}

// --- RunOnce (empty queue) ---

func TestRunOnce_EmptyQueue(t *testing.T) {
	s := mustNew(t, Config{
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
	if err := os.WriteFile(claimedFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(claimedFile, old, old); err != nil {
		t.Fatal(err)
	}

	fakeBin := buildFakeMailRemote(t)
	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	// processDomainDir directly -- no recovery pass, simulating concurrent scan.
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
	if err := os.WriteFile(staleClaimed, []byte(`{"msgid":"stale1234"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Also a normal envelope that shouldn't be touched.
	normalEnv := filepath.Join(envDir, "bob@normal5678.0")
	if err := os.WriteFile(normalEnv, []byte(`{"msgid":"normal5678"}`), 0600); err != nil {
		t.Fatal(err)
	}

	s := mustNew(t, Config{QueueDir: dir, Binary: "mail-remote", Interval: time.Minute})
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
	"encoding/json"
	"io"
	"os"
	"strings"
)

type result struct {
	Envelope   string ` + "`json:\"envelope\"`" + `
	Status     string ` + "`json:\"status\"`" + `
	SMTPCode   int    ` + "`json:\"smtp_code\"`" + `
	Diagnostic string ` + "`json:\"diagnostic\"`" + `
}

type outboundCfg struct {
	Strategy      string ` + "`json:\"strategy\"`" + `
	Smarthost     string ` + "`json:\"smarthost\"`" + `
	SmarthostUser string ` + "`json:\"smarthost_user\"`" + `
	Password      string ` + "`json:\"password\"`" + `
}

func main() {
	// Read outbound config from stdin (JSON from queue-manager).
	var ofc outboundCfg
	data, _ := io.ReadAll(os.Stdin)
	if len(data) > 0 {
		_ = json.Unmarshal(data, &ofc)
	}

	// Record args and outbound config to file for test assertions.
	recordFile := os.Getenv("QUEUE_MGR_RECORD_FILE")
	if recordFile != "" {
		args := strings.Join(os.Args[1:], "\n")
		if ofc.Smarthost != "" {
			args += "\nOUTBOUND_SMARTHOST=" + ofc.Smarthost
		}
		if ofc.SmarthostUser != "" {
			args += "\nOUTBOUND_USER=" + ofc.SmarthostUser
		}
		if ofc.Password != "" {
			args += "\nOUTBOUND_PASSWORD=" + ofc.Password
		}
		args += "\n---\n"
		f, _ := os.OpenFile(recordFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if f != nil {
			_, _ = f.WriteString(args)
			_ = f.Close()
		}
	}

	// Write JSON results to stdout (envelope paths start after flags and body).
	var results []result
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.Contains(arg, ".delivering") {
			results = append(results, result{
				Envelope: arg, Status: "delivered", SMTPCode: 250,
			})
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(results)
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

// buildFakeMailRemotePermFail compiles a fake mail-remote that reports all
// envelopes as perm_fail with a 550 SMTP code and exits with code 69.
func buildFakeMailRemotePermFail(t *testing.T) string {
	t.Helper()

	src := `package main

import (
	"encoding/json"
	"os"
	"strings"
)

type result struct {
	Envelope   string ` + "`json:\"envelope\"`" + `
	Status     string ` + "`json:\"status\"`" + `
	SMTPCode   int    ` + "`json:\"smtp_code\"`" + `
	Diagnostic string ` + "`json:\"diagnostic\"`" + `
}

func main() {
	var results []result
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.Contains(arg, ".delivering") {
			results = append(results, result{
				Envelope:   arg,
				Status:     "perm_fail",
				SMTPCode:   550,
				Diagnostic: "550 5.1.1 The email account does not exist.",
			})
			// Delete the envelope (mail-remote deletes on perm_fail).
			_ = os.Remove(arg)
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(results)
	os.Exit(69)
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "fake-mail-remote-permfail")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake mail-remote-permfail: %v", err)
	}
	return binPath
}

// mockDeliveryServer is a mock DeliveryService for testing DSN delivery.
type mockDeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer
	lastMeta *pb.DeliverMetadata
	lastBody []byte
}

func (m *mockDeliveryServer) Deliver(stream pb.DeliveryService_DeliverServer) error {
	var body bytes.Buffer
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			m.lastBody = body.Bytes()
			return stream.SendAndClose(&pb.DeliverResponse{
				Result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
			})
		}
		if err != nil {
			return err
		}
		switch p := req.Payload.(type) {
		case *pb.DeliverRequest_Metadata:
			m.lastMeta = p.Metadata
		case *pb.DeliverRequest_Data:
			body.Write(p.Data)
		}
	}
}

// --- DSN integration tests ---

func TestProcessDomainDir_DSNOnPermFail(t *testing.T) {
	fakeBin := buildFakeMailRemotePermFail(t)
	dir := t.TempDir()
	msgid := "dsntest1234"

	// Body file with headers.
	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	bodyContent := "From: user@example.com\r\nTo: alice@gmail.com\r\nSubject: Test\r\nMessage-ID: <" + msgid + "@example.com>\r\n\r\nBody text.\r\n"
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte(bodyContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Envelope with origin field.
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	ttl := time.Now().Add(24 * time.Hour).UTC()
	created := time.Now().Add(-1 * time.Hour).UTC()
	envContent := fmt.Sprintf(`{"ttl":"%s","created":"%s","sender":"user@example.com","recipient":"alice@gmail.com","msgid":"%s","origin":"user@example.com"}`,
		ttl.Format(time.RFC3339), created.Format(time.RFC3339), msgid)
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Start mock delivery server.
	mock := &mockDeliveryServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	// Create delivery client pointing to mock server.
	cl, err := delivery.NewClient(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Close() }()

	// Create scheduler with DSN enabled and inject the delivery client.
	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		Hostname: "mail.example.com",
		DSN:      config.DSNConfig{Enabled: true},
	})
	s.deliverer = cl

	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// Verify the mock delivery server received the DSN.
	if mock.lastMeta == nil {
		t.Fatal("expected DSN to be delivered to mock server")
	}
	if mock.lastMeta.Sender != "" {
		t.Errorf("DSN sender should be empty (null sender), got %q", mock.lastMeta.Sender)
	}
	if mock.lastMeta.Recipient != "user@example.com" {
		t.Errorf("DSN recipient = %q, want user@example.com", mock.lastMeta.Recipient)
	}

	// Verify the DSN body contains expected content.
	body := string(mock.lastBody)
	if !strings.Contains(body, "multipart/report") {
		t.Error("DSN body should contain multipart/report content type")
	}
	if !strings.Contains(body, "alice@gmail.com") {
		t.Error("DSN body should reference the failed recipient")
	}
	if !strings.Contains(body, "5.1.1") {
		t.Error("DSN body should contain enhanced status code from diagnostic")
	}
	if !strings.Contains(body, "MAILER-DAEMON@mail.example.com") {
		t.Error("DSN body should be from MAILER-DAEMON@hostname")
	}
	// Mid-queue perm_fail: ExpiredAt should not be set (message hasn't expired).
	if strings.Contains(body, "TTL expired") {
		t.Error("mid-queue perm_fail DSN should not mention TTL expiry")
	}
}

func TestProcessDomainDir_DSNSkippedWhenDisabled(t *testing.T) {
	fakeBin := buildFakeMailRemotePermFail(t)
	dir := t.TempDir()
	msgid := "nodsntest"

	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("From: a@b.com\r\n\r\nbody"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envContent := fmt.Sprintf(`{"msgid":"%s","origin":"user@example.com","recipient":"alice@gmail.com"}`, msgid)
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Start mock delivery server.
	mock := &mockDeliveryServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cl, err := delivery.NewClient(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Close() }()

	// DSN disabled -- should not deliver.
	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		Hostname: "mail.example.com",
		DSN:      config.DSNConfig{Enabled: false},
	})
	s.deliverer = cl

	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	if mock.lastMeta != nil {
		t.Error("expected no DSN delivery when DSN is disabled")
	}
}

func TestProcessDomainDir_DSNOnExpiredTempFail(t *testing.T) {
	// Fake mail-remote that returns temp_fail (but envelope is expired, so
	// the TTL expiry itself is a permanent failure deserving a DSN).
	src := `package main

import (
	"encoding/json"
	"os"
	"strings"
)

type result struct {
	Envelope   string ` + "`json:\"envelope\"`" + `
	Status     string ` + "`json:\"status\"`" + `
	SMTPCode   int    ` + "`json:\"smtp_code\"`" + `
	Diagnostic string ` + "`json:\"diagnostic\"`" + `
}

func main() {
	var results []result
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.Contains(arg, ".delivering") {
			results = append(results, result{
				Envelope:   arg,
				Status:     "temp_fail",
				SMTPCode:   421,
				Diagnostic: "421 4.7.0 Try again later",
			})
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(results)
	os.Exit(75)
}
`
	buildDir := t.TempDir()
	srcFile := filepath.Join(buildDir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(buildDir, "fake-mr-tempfail")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake mail-remote-tempfail: %v", err)
	}

	dir := t.TempDir()
	msgid := "expiredtempfail"

	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("From: a@b.com\r\n\r\nbody"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	// TTL in the past -- expired.
	ttl := time.Now().Add(-1 * time.Hour).UTC()
	created := time.Now().Add(-169 * time.Hour).UTC()
	envContent := fmt.Sprintf(`{"ttl":"%s","created":"%s","msgid":"%s","origin":"sender@example.com","recipient":"alice@gmail.com"}`,
		ttl.Format(time.RFC3339), created.Format(time.RFC3339), msgid)
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	mock := &mockDeliveryServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cl, err := delivery.NewClient(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Close() }()

	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   binPath,
		Interval: time.Minute,
		Hostname: "mail.example.com",
		DSN:      config.DSNConfig{Enabled: true},
	})
	s.deliverer = cl

	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// Even though the SMTP result was temp_fail, the envelope is expired,
	// so a DSN should be generated (TTL expiry = permanent failure).
	if mock.lastMeta == nil {
		t.Fatal("expected DSN for expired envelope with temp_fail")
	}
	if mock.lastMeta.Recipient != "sender@example.com" {
		t.Errorf("DSN recipient = %q, want sender@example.com (origin)", mock.lastMeta.Recipient)
	}

	// Expired envelope: the DSN should mention TTL expiry.
	body := string(mock.lastBody)
	if !strings.Contains(body, "TTL expired") {
		t.Error("expired envelope DSN should mention TTL expiry")
	}

	// Envelope should be deleted (expired).
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Error("expired envelope should be deleted")
	}
}

func TestProcessDomainDir_DSNMissingOrigin(t *testing.T) {
	fakeBin := buildFakeMailRemotePermFail(t)
	dir := t.TempDir()
	msgid := "noorigin"

	bodyDir := filepath.Join(dir, "msg", "com", "example")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("From: a@b.com\r\n\r\nbody"), 0600); err != nil {
		t.Fatal(err)
	}

	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	// No origin field -- pre-migration envelope.
	envContent := fmt.Sprintf(`{"msgid":"%s","recipient":"alice@gmail.com"}`, msgid)
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	mock := &mockDeliveryServer{}
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cl, err := delivery.NewClient(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Close() }()

	s := mustNew(t, Config{
		QueueDir: dir,
		Binary:   fakeBin,
		Interval: time.Minute,
		Hostname: "mail.example.com",
		DSN:      config.DSNConfig{Enabled: true},
	})
	s.deliverer = cl

	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	// No DSN should be delivered (missing origin).
	if mock.lastMeta != nil {
		t.Error("expected no DSN delivery when origin is missing")
	}
}

// --- outbound transport routing integration tests ---

// TestProcessDomainDir_SmarthostFromDomainConfig verifies that per-domain
// outbound config passes smarthost, user, and password via stdin JSON
// to mail-remote.
func TestProcessDomainDir_SmarthostFromDomainConfig(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "outbound1234"

	// Body file under msg/com/sender/ (sender domain = sender.com).
	bodyDir := filepath.Join(dir, "msg", "com", "sender")
	if err := os.MkdirAll(bodyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bodyDir, msgid), []byte("body data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Envelope for alice@gmail.com (recipient domain).
	envDir := filepath.Join(dir, "env", "com", "gmail")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(envDir, "alice@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Domain config for sender.com with smarthost.
	domainBase := t.TempDir()
	senderDir := filepath.Join(domainBase, "sender.com")
	if err := os.MkdirAll(senderDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "ses.us-east-1.amazonaws.com:587"
smarthost_user = "AKIAEXAMPLE"
password_file = "ses-password"
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "ses-password"), []byte("super-secret-pw\n"), 0600); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if !strings.Contains(args, "OUTBOUND_SMARTHOST=ses.us-east-1.amazonaws.com:587") {
		t.Errorf("expected OUTBOUND_SMARTHOST in record; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_USER=AKIAEXAMPLE") {
		t.Errorf("expected OUTBOUND_USER in record; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_PASSWORD=super-secret-pw") {
		t.Errorf("expected OUTBOUND_PASSWORD in record; got:\n%s", args)
	}
}

// TestProcessDomainDir_DirectDeliveryFromDomainConfig verifies that a domain
// with strategy = "direct" does NOT pass --smarthost args.
func TestProcessDomainDir_DirectDeliveryFromDomainConfig(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "direct5678"

	bodyDir := filepath.Join(dir, "msg", "net", "infodancer")
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
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Domain config for infodancer.net with strategy = "direct".
	domainBase := t.TempDir()
	senderDir := filepath.Join(domainBase, "infodancer.net")
	if err := os.MkdirAll(senderDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "config.toml"), []byte(`
[outbound]
strategy = "direct"
`), 0600); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
		Outbound: config.OutboundConfig{
			Strategy:      "smarthost",
			Smarthost:     "global-relay:587",
			SmarthostUser: "global-user",
		}, // should be ignored -- per-domain config takes precedence
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if strings.Contains(args, "OUTBOUND_SMARTHOST") {
		t.Errorf("expected NO OUTBOUND_SMARTHOST for direct delivery; got:\n%s", args)
	}
	if strings.Contains(args, "OUTBOUND_PASSWORD") {
		t.Errorf("expected NO OUTBOUND_PASSWORD for direct delivery; got:\n%s", args)
	}
}

// TestProcessDomainDir_FallbackToGlobalSmarthost verifies that when no domain
// config is found, the global [outbound] config is used.
func TestProcessDomainDir_FallbackToGlobalSmarthost(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "fallback9999"

	bodyDir := filepath.Join(dir, "msg", "com", "nocfg")
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
	envFile := filepath.Join(envDir, "carol@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// Domain config base exists but has no config for nocfg.com.
	domainBase := t.TempDir()

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
		Outbound: config.OutboundConfig{
			Strategy:      "smarthost",
			Smarthost:     "global-relay:587",
			SmarthostUser: "global-user",
		},
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if !strings.Contains(args, "OUTBOUND_SMARTHOST=global-relay:587") {
		t.Errorf("expected OUTBOUND_SMARTHOST=global-relay:587 in record; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_USER=global-user") {
		t.Errorf("expected OUTBOUND_USER=global-user in record; got:\n%s", args)
	}
}

// TestProcessDomainDir_SystemDefaultOutbound verifies that the system-wide
// default [outbound] config is used when no per-domain override exists.
func TestProcessDomainDir_SystemDefaultOutbound(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "sysdefault42"

	bodyDir := filepath.Join(dir, "msg", "com", "newdomain")
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
	envFile := filepath.Join(envDir, "dave@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// System default config with smarthost (no per-domain override).
	// The password_file is relative to the sender domain dir, so we
	// create the sender domain dir with the password file even though
	// there's no per-domain config.toml override.
	domainBase := t.TempDir()
	if err := os.WriteFile(filepath.Join(domainBase, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "system-relay:587"
smarthost_user = "system-user"
password_file = "system-pass"
`), 0600); err != nil {
		t.Fatal(err)
	}
	senderDir := filepath.Join(domainBase, "newdomain.com")
	if err := os.MkdirAll(senderDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "system-pass"), []byte("sys-pw\n"), 0600); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if !strings.Contains(args, "OUTBOUND_SMARTHOST=system-relay:587") {
		t.Errorf("expected OUTBOUND_SMARTHOST=system-relay:587 in record; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_USER=system-user") {
		t.Errorf("expected OUTBOUND_USER=system-user in record; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_PASSWORD=sys-pw") {
		t.Errorf("expected OUTBOUND_PASSWORD=sys-pw in record; got:\n%s", args)
	}
}

// TestProcessDomainDir_SmarthostUserFromFile verifies that smarthost_user_file
// is read and used as the SMTP AUTH username, and that it overrides any inline
// smarthost_user. This lets the secret Postmark server token be supplied via a
// file (not committed to config.toml), symmetric with password_file.
func TestProcessDomainDir_SmarthostUserFromFile(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "userfile777"

	bodyDir := filepath.Join(dir, "msg", "com", "tokendomain")
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
	envFile := filepath.Join(envDir, "erin@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// System default with an inline smarthost_user that should be overridden by
	// smarthost_user_file; both the token and password come from files relative
	// to the sender domain dir.
	domainBase := t.TempDir()
	if err := os.WriteFile(filepath.Join(domainBase, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "smtp.postmarkapp.com:587"
smarthost_user = "ignored-inline-user"
smarthost_user_file = "pm-token"
password_file = "pm-token"
`), 0600); err != nil {
		t.Fatal(err)
	}
	senderDir := filepath.Join(domainBase, "tokendomain.com")
	if err := os.MkdirAll(senderDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "pm-token"), []byte("server-token-xyz\n"), 0600); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if !strings.Contains(args, "OUTBOUND_USER=server-token-xyz") {
		t.Errorf("expected OUTBOUND_USER=server-token-xyz (from file); got:\n%s", args)
	}
	if strings.Contains(args, "OUTBOUND_USER=ignored-inline-user") {
		t.Errorf("inline smarthost_user should have been overridden by smarthost_user_file; got:\n%s", args)
	}
	if !strings.Contains(args, "OUTBOUND_PASSWORD=server-token-xyz") {
		t.Errorf("expected OUTBOUND_PASSWORD=server-token-xyz; got:\n%s", args)
	}
}

// TestProcessDomainDir_GlobalSmarthostUserFromFile verifies the same resolution
// via the in-process global fallback config (Config.Outbound), where the token
// file path resolves relative to DomainConfigPath.
func TestProcessDomainDir_GlobalSmarthostUserFromFile(t *testing.T) {
	fakeBin := buildFakeMailRemote(t)
	dir := t.TempDir()
	msgid := "globaluserfile88"

	bodyDir := filepath.Join(dir, "msg", "com", "nocfg")
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
	envFile := filepath.Join(envDir, "frank@"+msgid+".0")
	if err := os.WriteFile(envFile, []byte(fmt.Sprintf(`{"msgid":"%s"}`, msgid)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(envFile, old, old); err != nil {
		t.Fatal(err)
	}

	// No per-domain or system config.toml: fall back to Config.Outbound. The
	// token file resolves relative to DomainConfigPath.
	domainBase := t.TempDir()
	if err := os.WriteFile(filepath.Join(domainBase, "pm-token"), []byte("global-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	recordFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("QUEUE_MGR_RECORD_FILE", recordFile)

	s := mustNew(t, Config{
		QueueDir:         dir,
		Binary:           fakeBin,
		Interval:         time.Minute,
		DomainConfigPath: domainBase,
		Outbound: config.OutboundConfig{
			Strategy:          "smarthost",
			Smarthost:         "smtp.postmarkapp.com:587",
			SmarthostUserFile: "pm-token",
			PasswordFile:      "pm-token",
		},
	})
	if err := s.processDomainDir(envDir); err != nil {
		t.Fatalf("processDomainDir: %v", err)
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("reading record file: %v", err)
	}
	args := string(data)

	if !strings.Contains(args, "OUTBOUND_USER=global-token") {
		t.Errorf("expected OUTBOUND_USER=global-token (from file via global fallback); got:\n%s", args)
	}
}

// --- invoke: empty stdout / unparseable stdout on exit 0 ---

// buildFakeMailRemoteEmptyStdout compiles a fake mail-remote that exits 0
// with no output on stdout.
func buildFakeMailRemoteEmptyStdout(t *testing.T) string {
	t.Helper()
	src := `package main

func main() {}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "fake-mail-remote-empty")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake mail-remote-empty: %v", err)
	}
	return binPath
}

// buildFakeMailRemoteBadJSON compiles a fake mail-remote that exits 0 but
// writes non-JSON to stdout.
func buildFakeMailRemoteBadJSON(t *testing.T) string {
	t.Helper()
	src := `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stdout, "this is not json")
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "fake-mail-remote-badjson")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake mail-remote-badjson: %v", err)
	}
	return binPath
}

// TestInvoke_EmptyStdoutOnExit0 verifies that invoke returns an empty slice
// and does not panic when mail-remote exits 0 with no stdout output.
// The error-level log is not directly assertable here, but the function
// must not crash or hang.
func TestInvoke_EmptyStdoutOnExit0(t *testing.T) {
	fakeBin := buildFakeMailRemoteEmptyStdout(t)
	dir := t.TempDir()

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	results := s.invoke("body.txt", []string{"env1.txt"}, false, OutboundConfig{Strategy: "direct"})

	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

// TestInvoke_BadJSONOnExit0 verifies that invoke returns an empty slice
// and does not panic when mail-remote exits 0 with non-JSON stdout.
func TestInvoke_BadJSONOnExit0(t *testing.T) {
	fakeBin := buildFakeMailRemoteBadJSON(t)
	dir := t.TempDir()

	s := mustNew(t, Config{QueueDir: dir, Binary: fakeBin, Interval: time.Minute})
	results := s.invoke("body.txt", []string{"env1.txt"}, false, OutboundConfig{Strategy: "direct"})

	if len(results) != 0 {
		t.Errorf("expected empty results on parse failure, got %d", len(results))
	}
}
