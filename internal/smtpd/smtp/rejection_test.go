package smtp_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
)

// rejectionTestEnv extends testEnv with data-mode rejection and a spamtrap stub.
type rejectionTestEnv struct {
	addr      string
	configDir string
	mailDir   string
	domain    string
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// spamtrap stub
	learnMu    sync.Mutex
	learnCalls []learnCallRecord
}

type learnCallRecord struct {
	endpoint  string
	recipient string
	body      string
}

func newRejectionTestEnv(t *testing.T, mode config.RejectionMode, spamtrapEnabled bool) *rejectionTestEnv {
	t.Helper()

	configDir := t.TempDir()
	mailDir := t.TempDir()
	domainName := "test.local"

	domainConfigDir := filepath.Join(configDir, domainName)
	if err := os.MkdirAll(domainConfigDir, 0755); err != nil {
		t.Fatalf("mkdir domain config dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(domainConfigDir, "keys"), 0755); err != nil {
		t.Fatalf("mkdir keys dir: %v", err)
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

	env := &rejectionTestEnv{
		configDir: configDir,
		mailDir:   mailDir,
		domain:    domainName,
	}

	bcfg := smtpserver.BackendConfig{
		Hostname:       "test.local",
		DomainProvider: provider,
		AuthRouter:     authRouter,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
		TempDir:        t.TempDir(),
		RejectionMode:  mode,
	}

	if spamtrapEnabled {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			env.learnMu.Lock()
			env.learnCalls = append(env.learnCalls, learnCallRecord{
				endpoint:  r.URL.Path,
				recipient: r.Header.Get("Rcpt"),
				body:      string(body),
			})
			env.learnMu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)

		bcfg.SpamtrapConfig = config.SpamtrapConfig{
			Enabled:               true,
			ControllerURL:         srv.URL,
			MaxLearnsPerIPPerHour: 10,
		}
	}

	backend := smtpserver.NewBackend(bcfg)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	env.addr = ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: env.addr, Mode: config.ModeSmtp},
		},
		Hostname:       "test.local",
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel

	env.wg.Add(1)
	go func() {
		defer env.wg.Done()
		_ = srv.Run(ctx)
	}()

	// Wait for server to bind
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", env.addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		env.wg.Wait()
	})

	return env
}

func (env *rejectionTestEnv) addUser(t *testing.T, username, password string) {
	t.Helper()
	passwdFile := filepath.Join(env.configDir, env.domain, "passwd")
	if err := passwd.AddUser(passwdFile, username, password); err != nil {
		t.Fatalf("addUser %s: %v", username, err)
	}
}

func (env *rejectionTestEnv) getLearnCalls() []learnCallRecord {
	env.learnMu.Lock()
	defer env.learnMu.Unlock()
	result := make([]learnCallRecord, len(env.learnCalls))
	copy(result, env.learnCalls)
	return result
}

// TestRcptMode_RejectAtRcpt verifies default behavior: unknown user rejected at RCPT TO.
func TestRcptMode_RejectAtRcpt(t *testing.T) {
	env := newRejectionTestEnv(t, config.RejectionModeRcpt, false)
	env.addUser(t, "alice", "pass123")

	c := dialSMTP(t, env.addr)
	defer c.Quit(t)
	c.Greeting(t)
	c.Ehlo(t)

	c.mustCode(t, "MAIL FROM:<sender@remote.com>", 250)
	// Unknown user should get 550 at RCPT TO
	c.RcptExpect(t, "nobody@test.local", 550)
}

// TestDataMode_RejectAfterData verifies data-mode: unknown user accepted at RCPT TO,
// rejected after DATA.
func TestDataMode_RejectAfterData(t *testing.T) {
	env := newRejectionTestEnv(t, config.RejectionModeData, false)
	env.addUser(t, "alice", "pass123")

	c := dialSMTP(t, env.addr)
	defer c.Quit(t)
	c.Greeting(t)
	c.Ehlo(t)

	c.mustCode(t, "MAIL FROM:<sender@remote.com>", 250)
	// Unknown user should get 250 at RCPT TO (deferred)
	c.RcptExpect(t, "nobody@test.local", 250)
	// DATA should succeed (354)
	c.mustCode(t, "DATA", 354)
	// Send message body
	msg := "From: sender@remote.com\r\nTo: nobody@test.local\r\nSubject: test\r\n\r\nHello"
	if _, err := fmt.Fprintf(c.conn, "%s\r\n.\r\n", msg); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	// Should get 550 after DATA
	code, _ := c.readResponse(t)
	if code != 550 {
		t.Fatalf("expected 550 after DATA for unknown user, got %d", code)
	}
}

// TestDataMode_ValidUser verifies data-mode delivers normally for valid users.
func TestDataMode_ValidUser(t *testing.T) {
	env := newRejectionTestEnv(t, config.RejectionModeData, false)
	env.addUser(t, "alice", "pass123")

	c := dialSMTP(t, env.addr)
	defer c.Quit(t)
	c.Greeting(t)
	c.Ehlo(t)

	c.mustCode(t, "MAIL FROM:<sender@remote.com>", 250)
	c.RcptExpect(t, "alice@test.local", 250)
	c.mustCode(t, "DATA", 354)
	msg := "From: sender@remote.com\r\nTo: alice@test.local\r\nSubject: test\r\n\r\nHello"
	if _, err := fmt.Fprintf(c.conn, "%s\r\n.\r\n", msg); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	code, _ := c.readResponse(t)
	if code != 250 {
		t.Fatalf("expected 250 after DATA for valid user, got %d", code)
	}
}

// TestDataMode_SpamtrapAutoLearn verifies that messages to unknown users
// are auto-learned as spam when spamtrap is enabled.
func TestDataMode_SpamtrapAutoLearn(t *testing.T) {
	env := newRejectionTestEnv(t, config.RejectionModeData, true)
	env.addUser(t, "alice", "pass123")

	c := dialSMTP(t, env.addr)
	defer c.Quit(t)
	c.Greeting(t)
	c.Ehlo(t)

	c.mustCode(t, "MAIL FROM:<spammer@evil.com>", 250)
	c.RcptExpect(t, "nobody@test.local", 250)
	c.mustCode(t, "DATA", 354)
	msg := "From: spammer@evil.com\r\nTo: nobody@test.local\r\nSubject: spam\r\n\r\nBuy now!"
	if _, err := fmt.Fprintf(c.conn, "%s\r\n.\r\n", msg); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	code, _ := c.readResponse(t)
	if code != 550 {
		t.Fatalf("expected 550 after DATA, got %d", code)
	}

	// Verify auto-learn was called
	calls := env.getLearnCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 learn call, got %d", len(calls))
	}
	if calls[0].endpoint != "/learnspam" {
		t.Errorf("endpoint = %q, want /learnspam", calls[0].endpoint)
	}
	if calls[0].recipient != "nobody@test.local" {
		t.Errorf("recipient = %q, want nobody@test.local", calls[0].recipient)
	}
	if !strings.Contains(calls[0].body, "Buy now!") {
		t.Error("learn body should contain message content")
	}
}
