//go:build integration

package pop3_test

// TestSessionPipe_MailSession_Integration tests sessionPipeStore wired to a
// real mail-session process. It verifies List, Stat, Retrieve, Delete, and
// Expunge over the live session pipe protocol without any mocking.
//
// Requires the Go workspace (go.work) to be present so mail-session can be
// compiled. Run with:
//
//	go test -tags integration ./internal/pop3/ -run TestSessionPipe_MailSession

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/pop3d/pop3"
)

// workspaceRootForMailSession returns the workspace root containing go.work.
// Skips the test if not running inside a Go workspace.
func workspaceRootForMailSession(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOWORK").Output()
	if err != nil {
		t.Skipf("go env GOWORK: %v", err)
	}
	work := strings.TrimSpace(string(out))
	if work == "" || work == "off" {
		t.Skip("not running in a Go workspace; mail-session cannot be resolved")
	}
	return filepath.Dir(work)
}

// buildMailSessionBin compiles the mail-session binary into a temp dir.
// Skips the test if the build fails.
func buildMailSessionBin(t *testing.T) string {
	t.Helper()
	wsRoot := workspaceRootForMailSession(t)
	bin := filepath.Join(t.TempDir(), "mail-session")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/infodancer/maildancer/internal/mail-session/cmd/mail-session")
	cmd.Dir = wsRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("build mail-session failed: %v\n%s", err, out)
	}
	return bin
}

// makeMaildir creates a maildir tree at basePath/localpart/{cur,new,tmp} and
// delivers n test messages into new/.
func makeMaildir(t *testing.T, basePath, localpart string, n int) {
	t.Helper()
	for _, sub := range []string{"cur", "new", "tmp"} {
		dir := filepath.Join(basePath, localpart, sub)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("makeMaildir: mkdir %s: %v", dir, err)
		}
	}
	for i := range n {
		name := fmt.Sprintf("100000000%d.%05d.testhost", i, i)
		body := fmt.Sprintf(
			"From: sender@example.com\r\nTo: %s@test.local\r\nSubject: Message %d\r\n\r\nBody line %d\r\n",
			localpart, i+1, i+1,
		)
		path := filepath.Join(basePath, localpart, "new", name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatalf("makeMaildir: write %s: %v", path, err)
		}
	}
}

// countMaildirMessages returns the total number of files in cur/ and new/.
func countMaildirMessages(t *testing.T, basePath, localpart string) int {
	t.Helper()
	total := 0
	for _, sub := range []string{"cur", "new"} {
		entries, err := os.ReadDir(filepath.Join(basePath, localpart, sub))
		if err != nil {
			t.Fatalf("countMaildirMessages: %v", err)
		}
		total += len(entries)
	}
	return total
}

func TestSessionPipe_MailSession_Integration(t *testing.T) {
	mailSessionBin := buildMailSessionBin(t)

	basePath := t.TempDir()
	const localpart = "alice"
	const mailbox = localpart + "@test.local"
	makeMaildir(t, basePath, localpart, 2)

	// Create OS pipe pairs:
	//   authPipeR/W — auth signal (write-once by sessionPipeStore, read by dispatcher)
	//   fromSessR/W — mail-session stdout → protocol-handler
	//   toSessR/W   — protocol-handler → mail-session stdin
	authPipeR, authPipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("auth pipe: %v", err)
	}
	fromSessR, fromSessW, err := os.Pipe()
	if err != nil {
		t.Fatalf("fromSess pipe: %v", err)
	}
	toSessR, toSessW, err := os.Pipe()
	if err != nil {
		t.Fatalf("toSess pipe: %v", err)
	}

	// Spawn mail-session with stdin=toSessR, stdout=fromSessW.
	msCmd := exec.Command(mailSessionBin, "--type", "maildir", "--basepath", basePath)
	msCmd.Stdin = toSessR
	msCmd.Stdout = fromSessW
	msCmd.Stderr = os.Stderr
	if err := msCmd.Start(); err != nil {
		t.Fatalf("start mail-session: %v", err)
	}

	// Parent relinquishes the child-owned pipe ends.
	_ = toSessR.Close()
	_ = fromSessW.Close()

	// Drain the auth pipe in the background (simulates the dispatcher).
	// The sessionPipeStore closes authPipeW after writing; we must drain
	// authPipeR so the write never blocks, then close it.
	go func() {
		_, _ = io.Copy(io.Discard, authPipeR)
		_ = authPipeR.Close()
	}()

	// Build the sessionPipeStore — the same type injected by cmd/pop3d/handler.go.
	store := pop3.NewSessionPipeStore(authPipeW, fromSessR, toSessW)
	ctx := context.Background()

	// ── List ──────────────────────────────────────────────────────────────────
	// First call triggers the auth signal + MAILBOX handshake, then LIST.
	msgs, err := store.List(ctx, mailbox)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("List: expected 2 messages, got %d", len(msgs))
	}

	// ── Stat ──────────────────────────────────────────────────────────────────
	count, total, err := store.Stat(ctx, mailbox)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 2 {
		t.Errorf("Stat count: want 2, got %d", count)
	}
	if total <= 0 {
		t.Errorf("Stat total: want > 0, got %d", total)
	}

	// ── Retrieve ──────────────────────────────────────────────────────────────
	uid0 := msgs[0].UID
	rc, err := store.Retrieve(ctx, mailbox, uid0)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Retrieve ReadAll: %v", err)
	}
	if !strings.Contains(string(data), "From: sender@example.com") {
		t.Errorf("Retrieve: missing From header; got:\n%s", string(data))
	}

	// ── Delete + Expunge ─────────────────────────────────────────────────────
	// Delete one message then commit. COMMIT causes mail-session to exit.
	if err := store.Delete(ctx, mailbox, uid0); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Expunge(ctx, mailbox); err != nil {
		t.Fatalf("Expunge (COMMIT): %v", err)
	}

	// Wait for mail-session to exit cleanly (COMMIT triggers os.Exit(0)).
	if err := msCmd.Wait(); err != nil {
		t.Errorf("mail-session exited with error: %v", err)
	}

	// Verify one message was expunged from disk.
	if got := countMaildirMessages(t, basePath, localpart); got != 1 {
		t.Errorf("after delete+expunge: expected 1 message on disk, got %d", got)
	}
}
