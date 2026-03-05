package smtp_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/maildeliver"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
)

// buildFakeDeliver builds a minimal binary that reads all stdin and writes it
// to outFile, then exits 0. Used to verify the stdin payload format.
func buildFakeDeliver(t *testing.T, outFile string) string {
	t.Helper()
	src := fmt.Sprintf(`package main
import ("io";"os")
func main() { data,_:=io.ReadAll(os.Stdin); os.WriteFile(%q,data,0644) }`, outFile)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "fake.go")
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		t.Fatalf("write fake source: %v", err)
	}
	binPath := filepath.Join(dir, "fake-deliver")
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake deliver: %v\n%s", err, out)
	}
	return binPath
}

// buildMailDeliver builds the real mail-deliver binary into a temp dir.
func buildMailDeliver(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "mail-deliver")
	cmd := exec.Command("go", "build", "-o", binPath, "github.com/infodancer/maildancer/internal/smtpd/cmd/mail-deliver")
	cmd.Dir = "../../"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mail-deliver: %v\n%s", err, out)
	}
	return binPath
}

// TestExecDeliveryAgent_Format verifies the stdin payload is correctly
// formatted: a JSON line followed by the raw message bytes.
func TestExecDeliveryAgent_Format(t *testing.T) {
	t.Parallel()

	outFile := filepath.Join(t.TempDir(), "captured.bin")
	bin := buildFakeDeliver(t, outFile)

	agent := smtpserver.NewExecDeliveryAgent(smtpserver.ExecDeliveryConfig{
		Cmd:        bin,
		ConfigPath: "/nonexistent/smtpd.toml", // fake binary ignores it
	})

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
	}
	message := strings.NewReader("From: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n")

	if err := agent.Deliver(t.Context(), envelope, message); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading captured output: %v", err)
	}

	// First line must be valid JSON with correct fields.
	idx := strings.IndexByte(string(data), '\n')
	if idx < 0 {
		t.Fatal("no newline found in captured stdin — JSON line missing")
	}
	jsonLine := data[:idx]
	var req maildeliver.DeliverRequest
	if err := json.Unmarshal(jsonLine, &req); err != nil {
		t.Fatalf("JSON line is not a valid DeliverRequest: %v\ndata: %s", err, jsonLine)
	}
	if req.Version != maildeliver.Version {
		t.Errorf("version: got %d, want %d", req.Version, maildeliver.Version)
	}
	if req.Sender != "sender@example.com" {
		t.Errorf("sender: got %q, want %q", req.Sender, "sender@example.com")
	}
	if len(req.Recipients) != 1 || req.Recipients[0] != "rcpt@example.com" {
		t.Errorf("recipients: got %v, want [rcpt@example.com]", req.Recipients)
	}

	// SpamResult fields should be absent when no spam result set.
	if req.SpamAction != "" {
		t.Errorf("SpamAction should be empty, got %q", req.SpamAction)
	}
	if req.SpamScore != 0 {
		t.Errorf("SpamScore should be 0, got %f", req.SpamScore)
	}

	// Remainder after the JSON line must be the raw message bytes.
	rest := string(data[idx+1:])
	if !strings.Contains(rest, "Subject: test") {
		t.Errorf("message body not found after JSON line; got: %q", rest)
	}
}

// TestExecDeliveryAgent_SpamResult verifies that SpamResult on the envelope
// is serialized to the wire protocol correctly.
func TestExecDeliveryAgent_SpamResult(t *testing.T) {
	t.Parallel()

	outFile := filepath.Join(t.TempDir(), "captured.bin")
	bin := buildFakeDeliver(t, outFile)

	agent := smtpserver.NewExecDeliveryAgent(smtpserver.ExecDeliveryConfig{
		Cmd:        bin,
		ConfigPath: "/nonexistent/smtpd.toml",
	})

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
		SpamResult: &msgstore.SpamResult{
			Score:   8.3,
			Action:  "flag",
			Checker: "rspamd",
		},
	}
	message := strings.NewReader("Subject: spam test\r\n\r\nbody\r\n")

	if err := agent.Deliver(t.Context(), envelope, message); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading captured output: %v", err)
	}

	idx := strings.IndexByte(string(data), '\n')
	if idx < 0 {
		t.Fatal("no newline in captured stdin")
	}

	var req maildeliver.DeliverRequest
	if err := json.Unmarshal(data[:idx], &req); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if req.SpamScore != 8.3 {
		t.Errorf("SpamScore = %f, want 8.3", req.SpamScore)
	}
	if req.SpamAction != "flag" {
		t.Errorf("SpamAction = %q, want %q", req.SpamAction, "flag")
	}
	if req.SpamChecker != "rspamd" {
		t.Errorf("SpamChecker = %q, want %q", req.SpamChecker, "rspamd")
	}
}

// TestExecDeliveryAgent_Delivery is an end-to-end test: builds the real
// mail-deliver binary, creates a temp maildir, delivers a message, and
// verifies a file appears under the maildir.
func TestExecDeliveryAgent_Delivery(t *testing.T) {
	t.Parallel()

	mailDir := t.TempDir()
	configDir := t.TempDir()

	// Write a minimal smtpd.toml pointing at the temp maildir.
	configContent := fmt.Sprintf("[smtpd]\nhostname = \"deliver.local\"\n\n[smtpd.delivery]\ntype = \"maildir\"\nbase_path = %q\n", mailDir)
	configPath := filepath.Join(configDir, "smtpd.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := buildMailDeliver(t)

	agent := smtpserver.NewExecDeliveryAgent(smtpserver.ExecDeliveryConfig{
		Cmd:        bin,
		ConfigPath: configPath,
	})

	envelope := msgstore.Envelope{
		From:       "sender@example.com",
		Recipients: []string{"alice@deliver.local"},
	}
	message := strings.NewReader("From: sender@example.com\r\nTo: alice@deliver.local\r\nSubject: e2e test\r\n\r\nbody\r\n")

	if err := agent.Deliver(t.Context(), envelope, message); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	// Verify at least one file was written under mailDir.
	found := false
	if err := filepath.Walk(mailDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("walk mailDir: %v", err)
	}
	if !found {
		t.Error("no mail file found under mailDir after delivery")
	}
}
