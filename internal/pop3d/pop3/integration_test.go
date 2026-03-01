//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/infodancer/maildancer/auth/passwd"      // Register passwd backend
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir backend

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
)

func TestStack_POP3FullStack(t *testing.T) {
	// Create temp dir tree: domainsDir/test.local/{config.toml, passwd, keys/, users/alice/{new,cur,tmp}/}
	domainsDir := t.TempDir()
	domainDir := filepath.Join(domainsDir, "test.local")
	keysDir := filepath.Join(domainDir, "keys")
	aliceNewDir := filepath.Join(domainDir, "users", "alice", "new")
	aliceCurDir := filepath.Join(domainDir, "users", "alice", "cur")
	aliceTmpDir := filepath.Join(domainDir, "users", "alice", "tmp")

	for _, d := range []string{keysDir, aliceNewDir, aliceCurDir, aliceTmpDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Write domain config.toml.
	configTOML := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(configTOML), 0600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	// Generate argon2id hash for "testpass" and write passwd file.
	hash, err := hashPassword("testpass")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	passwdContent := fmt.Sprintf("alice:%s:alice\n", hash)
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwdContent), 0600); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	// Pre-populate alice's new/ with a test message.
	testMsg := "From: sender@example.com\r\nTo: alice@test.local\r\nSubject: Test\r\n\r\nHello, world!\r\n"
	if err := os.WriteFile(filepath.Join(aliceNewDir, "testmsg"), []byte(testMsg), 0600); err != nil {
		t.Fatalf("write testmsg: %v", err)
	}

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Build config.
	cfg := config.Default()
	cfg.Hostname = "test.local"
	cfg.DomainsPath = domainsDir
	cfg.Listeners = []config.ListenerConfig{
		{Address: addr, Mode: config.ModePop3},
	}
	cfg.Timeouts = config.TimeoutsConfig{
		Connection: "10s",
		Command:    "10s",
	}

	stack, err := pop3.NewStack(pop3.StackConfig{Config: cfg})
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

	go func() {
		if err := stack.Run(ctx); err != nil {
			t.Logf("stack.Run: %v", err)
		}
	}()

	// Wait for server to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connect.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	r := bufio.NewReader(conn)

	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		t.Logf("S: %s", line)
		return line
	}
	sendLine := func(s string) {
		t.Logf("C: %s", s)
		fmt.Fprintf(conn, "%s\r\n", s)
	}

	// Greeting.
	greeting := readLine()
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// USER.
	sendLine("USER alice@test.local")
	resp := readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER failed: %s", resp)
	}

	// PASS.
	sendLine("PASS testpass")
	resp = readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS failed: %s", resp)
	}

	// STAT — expect 1 message.
	sendLine("STAT")
	resp = readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT failed: %s", resp)
	}
	// Response is "+OK <count> <octets>"
	var count, octets int
	if _, err := fmt.Sscanf(resp, "+OK %d %d", &count, &octets); err != nil {
		t.Fatalf("parse STAT response %q: %v", resp, err)
	}
	if count != 1 {
		t.Fatalf("expected 1 message, got %d", count)
	}

	// QUIT.
	sendLine("QUIT")
	readLine()
}
