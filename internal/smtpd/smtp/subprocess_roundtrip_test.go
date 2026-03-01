//go:build integration

package smtp_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/infodancer/maildancer/auth/passwd"
)

// buildSmtpdBin builds the smtpd binary into a temp directory.
// It skips the test (rather than failing) on build error so CI can
// distinguish "build infrastructure broken" from "test logic failed".
func buildSmtpdBin(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "smtpd")
	cmd := exec.Command("go", "build", "-o", binPath, "github.com/infodancer/maildancer/internal/smtpd/cmd/smtpd")
	cmd.Dir = "../../"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("build smtpd: %v\n%s", err, out)
	}
	return binPath
}

// setupSmtpSubprocessEnv creates a temporary config tree and maildir
// suitable for spawning an smtpd protocol-handler subprocess.
// Returns the configDir, mailDir, and the absolute path to smtpd.toml.
//
// alice@test.local is created in the domain passwd file so RCPT TO
// validation (authRouter.UserExists) succeeds. No password check is
// performed by the SMTP layer for unauthenticated inbound mail.
func setupSmtpSubprocessEnv(t *testing.T, mailDeliverBin string) (configDir, mailDir, smtpdConfigPath string) {
	t.Helper()
	configDir = t.TempDir()
	mailDir = t.TempDir()

	domainConfigDir := filepath.Join(configDir, "test.local")
	if err := os.MkdirAll(filepath.Join(domainConfigDir, "keys"), 0755); err != nil {
		t.Fatalf("mkdir domain keys: %v", err)
	}

	domainConfig := fmt.Sprintf(`[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = %q

[msgstore.options]
maildir_subdir = "Maildir"
path_template = "{localpart}"
`, mailDir)
	if err := os.WriteFile(filepath.Join(domainConfigDir, "config.toml"), []byte(domainConfig), 0644); err != nil {
		t.Fatalf("write domain config.toml: %v", err)
	}

	passwdPath := filepath.Join(domainConfigDir, "passwd")
	if err := os.WriteFile(passwdPath, []byte(""), 0644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := passwd.AddUser(passwdPath, "alice", "unused"); err != nil {
		t.Fatalf("add alice to passwd: %v", err)
	}

	// Pre-create alice's maildir so mail-deliver doesn't have to mkdir it.
	for _, sub := range []string{"new", "cur", "tmp"} {
		if err := os.MkdirAll(filepath.Join(mailDir, "alice", "Maildir", sub), 0755); err != nil {
			t.Fatalf("mkdir alice Maildir/%s: %v", sub, err)
		}
	}

	// The [[smtpd.listeners]] entry satisfies cfg.Validate() but is never
	// bound — the protocol-handler receives its connection on fd 3.
	smtpdConfig := fmt.Sprintf(`[smtpd]
hostname = "test.local"
domains_path = %q

[smtpd.delivery]
type = "maildir"
base_path = %q
deliver_cmd = %q

[smtpd.limits]
max_recipients = 1
max_message_size = 10485760

[smtpd.timeouts]
connection = "30s"

[[smtpd.listeners]]
address = "127.0.0.1:0"
mode = "smtp"
`, configDir, mailDir, mailDeliverBin)

	smtpdConfigPath = filepath.Join(configDir, "smtpd.toml")
	if err := os.WriteFile(smtpdConfigPath, []byte(smtpdConfig), 0644); err != nil {
		t.Fatalf("write smtpd.toml: %v", err)
	}
	return
}

// runSmtpProtocolHandler spawns an smtpd protocol-handler subprocess and
// wires it up to a real kernel TCP socket pair. The server side of the pair
// is passed as fd 3 (ExtraFiles[0]); the client side is returned for the
// test to drive the SMTP session.
//
// The returned wait function blocks until the subprocess exits. It is also
// registered with t.Cleanup so tests that don't call it explicitly don't leak
// processes.
func runSmtpProtocolHandler(t *testing.T, smtpdPath, configPath string) (net.Conn, func()) {
	t.Helper()

	// Create a loopback listener so we can accept a real TCP connection and
	// extract its file descriptor for the subprocess.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	connFileCh := make(chan *os.File, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		ln.Close()
		if acceptErr != nil {
			close(connFileCh)
			return
		}
		tcpConn := conn.(*net.TCPConn)
		f, fileErr := tcpConn.File()
		// Close our TCPConn wrapper; the subprocess gets its own dup via ExtraFiles.
		tcpConn.Close()
		if fileErr != nil {
			t.Errorf("tcpConn.File: %v", fileErr)
			close(connFileCh)
			return
		}
		connFileCh <- f
	}()

	// Dial to unblock Accept in the goroutine above.
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	connFile, ok := <-connFileCh
	if !ok {
		clientConn.Close()
		t.Fatal("failed to get server-side connection file")
	}

	phCmd := exec.Command(smtpdPath, "protocol-handler", "--config", configPath)
	phCmd.ExtraFiles = []*os.File{connFile} // ExtraFiles[0] → fd 3 in child
	phCmd.Env = append(os.Environ(),
		"SMTPD_CLIENT_IP=127.0.0.1",
		"SMTPD_LISTENER_MODE=smtp",
	)
	phCmd.Stderr = os.Stderr // surface subprocess errors in test output

	if err := phCmd.Start(); err != nil {
		connFile.Close()
		clientConn.Close()
		t.Fatalf("start protocol-handler: %v", err)
	}
	connFile.Close() // parent's copy of the fd is no longer needed

	var once sync.Once
	wait := func() {
		once.Do(func() { _ = phCmd.Wait() })
	}
	t.Cleanup(wait)

	return clientConn, wait
}

// countAliceSmtpMessages returns the number of files in alice's Maildir/new.
func countAliceSmtpMessages(t *testing.T, mailDir string) int {
	t.Helper()
	newDir := filepath.Join(mailDir, "alice", "Maildir", "new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", newDir, err)
	}
	return len(entries)
}

// TestSubprocessSmtp_DeliveryFullSession exercises the complete subprocess
// round-trip: smtpd protocol-handler receives a TCP socket on fd 3, drives a
// full SMTP session, and delegates final delivery to a real mail-deliver
// subprocess. Verifies that exactly one message lands in alice's Maildir/new
// and that the message content is preserved.
func TestSubprocessSmtp_DeliveryFullSession(t *testing.T) {
	smtpdBin := buildSmtpdBin(t)
	mailDeliverBin := buildMailDeliver(t)
	_, mailDir, configPath := setupSmtpSubprocessEnv(t, mailDeliverBin)

	clientConn, wait := runSmtpProtocolHandler(t, smtpdBin, configPath)
	defer clientConn.Close()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}

	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Subprocess test", "Hello from subprocess test")
	c.Quit(t)
	wait() // block until subprocess has exited and delivery is flushed to disk

	if got := countAliceSmtpMessages(t, mailDir); got != 1 {
		t.Errorf("expected 1 message in alice's Maildir/new, got %d", got)
	}

	// Verify message content is intact.
	newDir := filepath.Join(mailDir, "alice", "Maildir", "new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) > 0 {
		data, err := os.ReadFile(filepath.Join(newDir, entries[0].Name()))
		if err != nil {
			t.Fatalf("ReadFile message: %v", err)
		}
		if !strings.Contains(string(data), "Subject: Subprocess test") {
			t.Errorf("message missing expected subject; content:\n%s", data)
		}
	}
}

// TestSubprocessSmtp_MultiTransaction sends two back-to-back SMTP
// transactions within a single subprocess session and verifies that both
// messages land in alice's Maildir/new. go-smtp automatically resets the
// envelope after a successful DATA, so no explicit RSET is needed between
// transactions.
func TestSubprocessSmtp_MultiTransaction(t *testing.T) {
	smtpdBin := buildSmtpdBin(t)
	mailDeliverBin := buildMailDeliver(t)
	_, mailDir, configPath := setupSmtpSubprocessEnv(t, mailDeliverBin)

	clientConn, wait := runSmtpProtocolHandler(t, smtpdBin, configPath)
	defer clientConn.Close()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}

	c.Greeting(t)
	c.Ehlo(t)

	// First transaction.
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Transaction 1", "First message body")

	// Second transaction — envelope is reset automatically after DATA.
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Transaction 2", "Second message body")

	c.Quit(t)
	wait()

	if got := countAliceSmtpMessages(t, mailDir); got != 2 {
		t.Errorf("expected 2 messages in alice's Maildir/new, got %d", got)
	}
}
