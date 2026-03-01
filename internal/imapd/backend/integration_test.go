//go:build integration

package backend_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/infodancer/maildancer/auth/passwd" // Register passwd backend
	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // Register maildir backend
	"golang.org/x/crypto/argon2"
)

// hashPassword generates an argon2id hash in the format the passwd agent expects.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func TestStack_IMAPFullStack(t *testing.T) {
	// Create a temp dir tree mirroring the testdata fixture.
	// domainsDir/test.local/{config.toml, passwd, keys/, users/alice/new/}
	domainsDir := t.TempDir()
	domainDir := filepath.Join(domainsDir, "test.local")
	keysDir := filepath.Join(domainDir, "keys")
	usersDir := filepath.Join(domainDir, "users")
	aliceNewDir := filepath.Join(usersDir, "alice", "new")
	aliceCurDir := filepath.Join(usersDir, "alice", "cur")
	aliceTmpDir := filepath.Join(usersDir, "alice", "tmp")

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

	// Pick a free port for the test listener.
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
		{Address: addr, Mode: config.ModeImap},
	}

	stack, err := backend.NewStack(backend.StackConfig{
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	defer stack.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := stack.Run(ctx); err != nil {
			t.Logf("stack.Run: %v", err)
		}
	}()

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Connect and run IMAP conversation.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	r := bufio.NewReader(conn)

	// Read greeting.
	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}
	t.Logf("S: %s", strings.TrimRight(greeting, "\r\n"))

	// Helper: send a command and collect responses until the tagged response.
	sendCmd := func(tag, cmd string) []string {
		t.Helper()
		_, werr := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		if werr != nil {
			t.Fatalf("write %s: %v", tag, werr)
		}
		t.Logf("C: %s %s", tag, cmd)
		var lines []string
		for {
			line, rerr := r.ReadString('\n')
			if rerr != nil {
				t.Fatalf("read response for %s: %v", tag, rerr)
			}
			line = strings.TrimRight(line, "\r\n")
			t.Logf("S: %s", line)
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		return lines
	}

	// LOGIN — must use fully-qualified address; bare localpart has no domain for AuthRouter to route.
	loginResp := sendCmd("A1", "LOGIN alice@test.local testpass")
	tagged := loginResp[len(loginResp)-1]
	if !strings.HasPrefix(tagged, "A1 OK") {
		t.Fatalf("LOGIN failed: %s", tagged)
	}

	// SELECT INBOX
	selectResp := sendCmd("A2", "SELECT INBOX")
	tagged = selectResp[len(selectResp)-1]
	if !strings.HasPrefix(tagged, "A2 OK") {
		t.Fatalf("SELECT INBOX failed: %s", tagged)
	}

	// Find the EXISTS line and assert 1 message.
	var existsLine string
	for _, line := range selectResp {
		if strings.Contains(line, "EXISTS") {
			existsLine = line
			break
		}
	}
	if existsLine == "" {
		t.Fatalf("no EXISTS line in SELECT response: %v", selectResp)
	}
	if !strings.HasPrefix(existsLine, "* 1 EXISTS") {
		t.Fatalf("expected '* 1 EXISTS', got %q", existsLine)
	}

	// LOGOUT
	sendCmd("A3", "LOGOUT")
}
