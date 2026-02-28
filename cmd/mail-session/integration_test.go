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

// Ensure the integration test file compiles even without the build tag context.
var _ = fmt.Sprintf
var _ = io.EOF
