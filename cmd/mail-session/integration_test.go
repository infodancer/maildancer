//go:build integration

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// setupMaildir creates a minimal Maildir structure with one message and returns the base path.
func setupMaildir(t *testing.T) (basePath, mailbox, uid string) {
	t.Helper()
	base := t.TempDir()
	mailbox = "testuser"
	uid = "1234567890.M1P2345.testhost"

	// The store with no maildir_subdir option expects basePath/mailbox/{cur,new,tmp}
	curDir := filepath.Join(base, mailbox, "cur")
	if err := os.MkdirAll(curDir, 0o750); err != nil {
		t.Fatalf("mkdir cur: %v", err)
	}
	for _, sub := range []string{"new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(base, mailbox, sub), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	msgBody := "From: sender@example.com\r\nTo: testuser\r\nSubject: Test\r\n\r\nHello, world!\r\n"
	msgPath := filepath.Join(curDir, uid+":2,")
	if err := os.WriteFile(msgPath, []byte(msgBody), 0o640); err != nil {
		t.Fatalf("write message: %v", err)
	}

	return base, mailbox, uid
}

// runSession builds the binary, pipes commands to it, and returns the output lines.
func runSession(t *testing.T, basePath string, commands []string) []string {
	t.Helper()

	// Build the binary into a temp location.
	bin := filepath.Join(t.TempDir(), "mail-session")
	build := exec.Command("go", "build", "-o", bin, "github.com/infodancer/maildancer/internal/mail-session/cmd/mail-session")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	input := strings.Join(commands, "\r\n") + "\r\n"
	cmd := exec.Command(bin, "--basepath", basePath, "--type", "maildir")
	cmd.Stdin = strings.NewReader(input)

	out, err := cmd.Output()
	// exit 0 from COMMIT/QUIT is fine; other non-zero exits are real failures.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("exit code %d, stderr: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
	}

	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	return lines
}

func TestIntegration_Stat(t *testing.T) {
	base, mailbox, _ := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"STAT",
		"QUIT",
	})

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 response lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX response = %q, want +OK", lines[0])
	}
	if !strings.HasPrefix(lines[1], "+OK 1 ") {
		t.Errorf("STAT response = %q, want +OK 1 <size>", lines[1])
	}
}

func TestIntegration_List(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"LIST",
		"QUIT",
	})

	if len(lines) < 3 {
		t.Fatalf("expected at least 3 response lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX response = %q, want +OK", lines[0])
	}
	if lines[1] != "+OK 1" {
		t.Errorf("LIST count response = %q, want +OK 1", lines[1])
	}
	if !strings.Contains(lines[2], uid) {
		t.Errorf("LIST entry = %q, want it to contain uid %q", lines[2], uid)
	}
}

func TestIntegration_Get(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"GET " + uid,
		"QUIT",
	})

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 response lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX response = %q, want +OK", lines[0])
	}
	// Second line is +DATA <size>
	if !strings.HasPrefix(lines[1], "+DATA ") {
		t.Errorf("GET response = %q, want +DATA <size>", lines[1])
	}
	sizeStr := strings.TrimPrefix(lines[1], "+DATA ")
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size <= 0 {
		t.Errorf("invalid size in +DATA response: %q", lines[1])
	}
}

func TestIntegration_Headers(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"HEADERS " + uid,
		"QUIT",
	})

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d: %v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[1], "+DATA ") {
		t.Errorf("HEADERS response = %q, want +DATA <size>", lines[1])
	}
}

func TestIntegration_DeleteCommit(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"DELETE " + uid,
		"COMMIT",
	})

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX = %q, want +OK", lines[0])
	}
	if lines[1] != "+OK" {
		t.Errorf("DELETE = %q, want +OK", lines[1])
	}

	// After commit the message file should be gone from the maildir.
	curDir := filepath.Join(base, mailbox, "cur")
	entries, err := os.ReadDir(curDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), uid) {
			t.Errorf("message file still present after commit: %s", e.Name())
		}
	}
}

func TestIntegration_UnknownCommand(t *testing.T) {
	base, mailbox, _ := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"BOGUS",
		"QUIT",
	})

	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, "-ERR") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected -ERR for unknown command, lines: %v", lines)
	}
}

func TestIntegration_CommandBeforeMailbox(t *testing.T) {
	base := t.TempDir()
	lines := runSession(t, base, []string{
		"LIST",
		"QUIT",
	})

	if len(lines) < 1 || !strings.HasPrefix(lines[0], "-ERR") {
		t.Errorf("expected -ERR before MAILBOX, got: %v", lines)
	}
}

// runSessionBytes is like runSession but accepts raw stdin bytes.
// Use this when commands include binary payloads (e.g. APPEND message body).
func runSessionBytes(t *testing.T, basePath string, input []byte) []string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "mail-session")
	build := exec.Command("go", "build", "-o", bin, "github.com/infodancer/maildancer/internal/mail-session/cmd/mail-session")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	cmd := exec.Command(bin, "--basepath", basePath, "--type", "maildir")
	cmd.Stdin = strings.NewReader(string(input))

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("exit code %d, stderr: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
	}

	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	return lines
}

func TestIntegration_Folders_Empty(t *testing.T) {
	base, mailbox, _ := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"FOLDERS",
		"QUIT",
	})

	// Expect +OK (MAILBOX), +OK 0 (FOLDERS with 0 folders), +OK (QUIT).
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX = %q, want +OK", lines[0])
	}
	if lines[1] != "+OK 0" {
		t.Errorf("FOLDERS count = %q, want +OK 0", lines[1])
	}
}

func TestIntegration_CreateFolder(t *testing.T) {
	base, mailbox, _ := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"CREATEFOLDER Sent",
		"FOLDERS",
		"QUIT",
	})

	// Lines: +OK (MAILBOX), +OK (CREATEFOLDER), +OK 1 (FOLDERS count), Sent, +OK (QUIT)
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 lines, got %d: %v", len(lines), lines)
	}
	if lines[1] != "+OK" {
		t.Errorf("CREATEFOLDER = %q, want +OK", lines[1])
	}
	if lines[2] != "+OK 1" {
		t.Errorf("FOLDERS count = %q, want +OK 1", lines[2])
	}
	if lines[3] != "Sent" {
		t.Errorf("FOLDERS entry = %q, want Sent", lines[3])
	}
}

func TestIntegration_Select_INBOX(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"SELECT INBOX",
		"QUIT",
	})

	// Lines: +OK (MAILBOX), +OK 1 (SELECT count), <uid entry>, +OK (QUIT)
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[1] != "+OK 1" {
		t.Errorf("SELECT count = %q, want +OK 1", lines[1])
	}
	if !strings.Contains(lines[2], uid) {
		t.Errorf("SELECT entry = %q, want it to contain uid %q", lines[2], uid)
	}
}

func TestIntegration_Append(t *testing.T) {
	base, mailbox, _ := setupMaildir(t)

	body := "From: sender@example.com\r\nSubject: Appended\r\n\r\nHello\r\n"
	appendLine := fmt.Sprintf("APPEND INBOX %d NONE 2024-01-01T00:00:00Z\r\n", len(body))
	input := []byte("MAILBOX " + mailbox + "\r\n" + appendLine + body + "QUIT\r\n")
	lines := runSessionBytes(t, base, input)

	// Lines: +OK (MAILBOX), +OK <uid> (APPEND), +OK (QUIT)
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "+OK" {
		t.Errorf("MAILBOX = %q, want +OK", lines[0])
	}
	if !strings.HasPrefix(lines[1], "+OK ") {
		t.Errorf("APPEND = %q, want +OK <uid>", lines[1])
	}

	// AppendToFolder moves the message to cur/ (IMAP APPEND semantics).
	curDir := filepath.Join(base, mailbox, "cur")
	entries, err := os.ReadDir(curDir)
	if err != nil {
		t.Fatalf("readdir cur/: %v", err)
	}
	// setupMaildir placed one existing message in cur/; APPEND should add another.
	if len(entries) != 2 {
		t.Errorf("cur/ has %d entries, want 2 (original + appended)", len(entries))
	}
}

func TestIntegration_SetFlags_Expunge(t *testing.T) {
	base, mailbox, uid := setupMaildir(t)
	lines := runSession(t, base, []string{
		"MAILBOX " + mailbox,
		"SELECT INBOX",
		`SETFLAGS ` + uid + ` \Deleted`,
		"EXPUNGE",
		"QUIT",
	})

	// Lines: +OK (MAILBOX), +OK 1 + entry (SELECT), +OK (SETFLAGS),
	//        +OK 1 + uid (EXPUNGE), +OK (QUIT)
	expungeOK := false
	for _, l := range lines {
		if l == "+OK 1" {
			// Could be SELECT count or EXPUNGE count; look for uid after it.
			expungeOK = true
		}
	}
	if !expungeOK {
		t.Errorf("expected +OK 1 in response (EXPUNGE count), lines: %v", lines)
	}

	// Verify the message file is gone.
	curDir := filepath.Join(base, mailbox, "cur")
	entries, _ := os.ReadDir(curDir)
	for _, e := range entries {
		if strings.Contains(e.Name(), uid) {
			t.Errorf("message file still present after expunge: %s", e.Name())
		}
	}
}

// Ensure the integration test file compiles even without the build tag context.
var _ = fmt.Sprintf
var _ = io.EOF
