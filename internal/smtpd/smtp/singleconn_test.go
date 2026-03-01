package smtp_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
)

// newSingleConnEnv creates a minimal Server (no listener started) for use
// with RunSingleConn tests. Returns the server, a configDir, and a mailDir.
func newSingleConnEnv(t *testing.T) (*smtpserver.Server, string, string) {
	t.Helper()

	configDir := t.TempDir()
	mailDir := t.TempDir()
	domainName := "single.local"

	domainConfigDir := filepath.Join(configDir, domainName)
	if err := os.MkdirAll(filepath.Join(domainConfigDir, "keys"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configContent := fmt.Sprintf(`[auth]
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
	if err := os.WriteFile(filepath.Join(domainConfigDir, "config.toml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(domainConfigDir, "passwd"), []byte(""), 0644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	provider := domain.NewFilesystemDomainProvider(configDir, nil)
	authRouter := domain.NewAuthRouter(provider, nil)

	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:       "single.local",
		DomainProvider: provider,
		AuthAgent:      authRouter,
		AuthRouter:     authRouter,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
		TempDir:        t.TempDir(),
	})

	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: "127.0.0.1:0", Mode: config.ModeSmtp},
		},
		Hostname:       "single.local",
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return srv, configDir, mailDir
}

// addSingleConnUser adds a user to the single.local domain passwd file.
func addSingleConnUser(t *testing.T, configDir, username, password string) {
	t.Helper()
	passwdFile := filepath.Join(configDir, "single.local", "passwd")
	if err := passwd.AddUser(passwdFile, username, password); err != nil {
		t.Fatalf("addUser %s: %v", username, err)
	}
}

// TestRunSingleConn_BasicDelivery verifies that RunSingleConn handles a
// complete SMTP DATA transaction over a net.Pipe connection and delivers mail.
// This is the core invariant of the protocol-handler subprocess model.
func TestRunSingleConn_BasicDelivery(t *testing.T) {
	t.Parallel()

	srv, configDir, mailDir := newSingleConnEnv(t)
	addSingleConnUser(t, configDir, "carol", "pass")

	// net.Pipe gives a synchronous in-memory connection pair.
	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.RunSingleConn(serverConn, config.ModeSmtp, nil); err != nil {
			// ErrClosed is expected when the session ends normally.
			if !strings.Contains(err.Error(), "closed") {
				t.Errorf("RunSingleConn: unexpected error: %v", err)
			}
		}
	}()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "carol@single.local", "Test via RunSingleConn", "body text")
	c.Quit(t)
	_ = clientConn.Close()

	wg.Wait()

	// Verify delivery landed in mailDir.
	found := containsFile(t, mailDir, func(string) bool { return true })
	if !found {
		t.Error("no files found under mailDir after RunSingleConn delivery")
	}
}

// TestRunSingleConn_SessionEndsAfterQuit verifies that RunSingleConn returns
// after the client sends QUIT — the server does not hang indefinitely.
func TestRunSingleConn_SessionEndsAfterQuit(t *testing.T) {
	t.Parallel()

	srv, _, _ := newSingleConnEnv(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.RunSingleConn(serverConn, config.ModeSmtp, nil) //nolint:errcheck
		close(done)
	}()

	c := &smtpClient{conn: clientConn, r: bufio.NewReader(clientConn)}
	c.Greeting(t)
	c.Ehlo(t)
	c.Quit(t)
	_ = clientConn.Close()

	select {
	case <-done:
		// good: RunSingleConn returned after QUIT
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after QUIT")
	}
}

// TestRunSingleConn_NoSecondConn verifies that after the first connection is
// served, RunSingleConn returns rather than waiting for another connection.
func TestRunSingleConn_NoSecondConn(t *testing.T) {
	t.Parallel()

	srv, _, _ := newSingleConnEnv(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.RunSingleConn(serverConn, config.ModeSmtp, nil) //nolint:errcheck
		close(done)
	}()

	// Abruptly close the client side; RunSingleConn should notice and return.
	_ = clientConn.Close()

	select {
	case <-done:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after client disconnect")
	}
}
