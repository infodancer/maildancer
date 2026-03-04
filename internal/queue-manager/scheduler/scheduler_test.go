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

	// Set mtime to 10 minutes ago — should be ready.
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(f.Name(), old, old); err != nil {
		t.Fatal(err)
	}

	s := New(Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if !s.isReady(f.Name()) {
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
	if s.isReady(f.Name()) {
		t.Error("expected isReady=false for just-created file")
	}
}

func TestIsReady_MissingFile(t *testing.T) {
	s := New(Config{QueueDir: t.TempDir(), Binary: "mail-remote", Interval: time.Minute})
	if s.isReady("/nonexistent/path/file") {
		t.Error("expected isReady=false for missing file")
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
	args := strings.Join(os.Args[1:], "\n")
	_ = os.WriteFile(recordFile, []byte(args), 0600)
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
