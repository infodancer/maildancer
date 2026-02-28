//go:build integration

package smtp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/infodancer/maildancer/auth/passwd"    // register passwd auth backend
	_ "github.com/infodancer/maildancer/msgstore/maildir" // register maildir backend

	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// TestStack_DeliveryFullStack verifies that NewStack wires up all components
// correctly and that a message delivered via raw SMTP lands in the maildir.
func TestStack_DeliveryFullStack(t *testing.T) {
	// Separate dirs: configDir holds domain configs, mailDir holds mail data.
	configDir := t.TempDir()
	mailDir := t.TempDir()

	domainName := "test.local"
	domainConfigDir := filepath.Join(configDir, domainName)
	if err := os.MkdirAll(filepath.Join(domainConfigDir, "keys"), 0755); err != nil {
		t.Fatalf("mkdir domain config: %v", err)
	}

	// Domain config uses an absolute base_path so mail goes to mailDir.
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
		t.Fatalf("write config.toml: %v", err)
	}
	// Empty passwd — unauthenticated delivery only.
	if err := os.WriteFile(filepath.Join(domainConfigDir, "passwd"), []byte(""), 0644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	// Pre-allocate a free port (same strategy as roundtrip_test.go).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	cfg := config.Config{
		Hostname:    domainName,
		DomainsPath: configDir,
		Delivery: config.DeliveryConfig{
			Type:     "maildir",
			BasePath: mailDir,
			Options: map[string]string{
				"maildir_subdir": "Maildir",
				"path_template":  "{localpart}",
			},
		},
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Limits: config.LimitsConfig{
			MaxRecipients:  10,
			MaxMessageSize: 10 * 1024 * 1024,
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5s",
		},
	}

	stack, err := smtpserver.NewStack(smtpserver.StackConfig{Config: cfg})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() {
		if err := stack.Close(); err != nil {
			t.Logf("stack.Close: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = stack.Run(ctx) }()

	// Wait for the server to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Deliver a message via raw SMTP.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	readLine := func() string {
		line, _ := r.ReadString('\n')
		return line
	}
	sendLine := func(s string) {
		fmt.Fprintf(conn, "%s\r\n", s)
	}

	// Greeting
	line := readLine()
	if len(line) < 3 || line[:3] != "220" {
		t.Fatalf("expected 220 greeting, got: %s", line)
	}

	// EHLO
	sendLine("EHLO localhost")
	for {
		l := readLine()
		if len(l) >= 4 && l[3] == ' ' {
			break
		}
		if len(l) < 4 {
			break
		}
	}

	// MAIL FROM
	sendLine("MAIL FROM:<sender@example.com>")
	line = readLine()
	if line[:3] != "250" {
		t.Fatalf("MAIL FROM: expected 250, got %s", line)
	}

	// RCPT TO — alice must exist in the domain (empty passwd means no users,
	// so we need to add alice; the domain provider validates via auth backend).
	// Since passwd is empty and delivery validation goes through domain provider,
	// use an addUser approach: write alice's entry.
	// Actually: close the conn, add user, reconnect.
	sendLine("QUIT")
	readLine()
	conn.Close()

	// Add alice to the passwd file.
	alicePasswd := "alice:$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy\n"
	if err := os.WriteFile(filepath.Join(domainConfigDir, "passwd"), []byte(alicePasswd), 0644); err != nil {
		t.Fatalf("write alice passwd: %v", err)
	}

	// Reconnect and deliver.
	conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial2 %s: %v", addr, err)
	}
	defer conn2.Close()

	r2 := bufio.NewReader(conn2)
	read2 := func() string { l, _ := r2.ReadString('\n'); return l }
	send2 := func(s string) { fmt.Fprintf(conn2, "%s\r\n", s) }

	// Read greeting
	if l := read2(); len(l) < 3 || l[:3] != "220" {
		t.Fatalf("greeting2: got %s", l)
	}
	// EHLO
	send2("EHLO localhost")
	for {
		l := read2()
		if len(l) >= 4 && l[3] == ' ' {
			break
		}
		if len(l) < 4 {
			break
		}
	}
	// MAIL FROM
	send2("MAIL FROM:<sender@example.com>")
	if l := read2(); l[:3] != "250" {
		t.Fatalf("MAIL FROM2: %s", l)
	}
	// RCPT TO
	send2("RCPT TO:<alice@test.local>")
	if l := read2(); l[:3] != "250" {
		t.Fatalf("RCPT TO alice: %s", l)
	}
	// DATA
	send2("DATA")
	if l := read2(); l[:3] != "354" {
		t.Fatalf("DATA: %s", l)
	}
	fmt.Fprintf(conn2, "From: sender@example.com\r\nTo: alice@test.local\r\nSubject: Integration test\r\n\r\nHello, Stack!\r\n.\r\n")
	if l := read2(); l[:3] != "250" {
		t.Fatalf("DATA end: %s", l)
	}
	// QUIT
	send2("QUIT")
	read2()

	// Verify message landed in mailDir under alice's mailbox.
	aliceMaildir := filepath.Join(mailDir, "alice", "Maildir", "new")
	entries, err := os.ReadDir(aliceMaildir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", aliceMaildir, err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 message in alice's maildir/new, got %d", len(entries))
	}
}
