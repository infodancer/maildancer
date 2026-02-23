package smtp_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir" // register maildir backend
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
	"github.com/infodancer/maildancer/internal/smtpd/config"
)

// testEnv holds the infrastructure for a round-trip SMTP integration test.
// configDir simulates /etc/infodancer (read-only domain configs).
// mailDir simulates /opt/infodancer/domains (writable mail data).
// Both are separate t.TempDir() so tests can verify mail doesn't land in
// the config tree (regression for the absolute base_path bug).
type testEnv struct {
	addr      string
	configDir string
	mailDir   string
	domain    string
	clientTLS *tls.Config // for STARTTLS upgrade in auth tests
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// generateTestTLS generates a self-signed ECDSA certificate for testing.
// Returns server and client TLS configs.
func generateTestTLS(t *testing.T) (serverCfg, clientCfg *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		DNSNames:     []string{"test.local", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	serverCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	clientCfg = &tls.Config{RootCAs: pool, ServerName: "test.local"}
	return
}

func newTestEnv(t *testing.T) *testEnv {
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

	// Use an absolute base_path (mailDir) and path_template = "{localpart}" so
	// SMTP delivery and POP3 retrieval resolve to the same mailbox directory.
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

	serverTLS, clientTLS := generateTestTLS(t)

	// Pre-allocate a port. There is a small TOCTOU window but this is
	// acceptable in test environments.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:       "test.local",
		DomainProvider: provider,
		AuthAgent:      authRouter, // non-nil enables PLAIN advertisement; actual auth goes through AuthRouter
		AuthRouter:     authRouter,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
	})

	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Hostname:       "test.local",
		TLSConfig:      serverTLS,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	env := &testEnv{
		addr:      addr,
		configDir: configDir,
		mailDir:   mailDir,
		domain:    domainName,
		clientTLS: clientTLS,
		cancel:    cancel,
	}

	env.wg.Add(1)
	go func() {
		defer env.wg.Done()
		_ = srv.Run(ctx)
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

	t.Cleanup(func() {
		cancel()
		env.wg.Wait()
	})

	return env
}

// addUser writes a user entry to the domain passwd file.
// All users must be added before the first connection because the
// domain provider caches the parsed domain on first load.
func (env *testEnv) addUser(t *testing.T, username, password string) {
	t.Helper()
	passwdFile := filepath.Join(env.configDir, env.domain, "passwd")
	if err := passwd.AddUser(passwdFile, username, password); err != nil {
		t.Fatalf("addUser %s: %v", username, err)
	}
}

// countMessages opens a verification store and returns the number of messages
// in the given user's mailbox. Username is the local part only (e.g. "alice").
func (env *testEnv) countMessages(t *testing.T, username string) int {
	t.Helper()
	msgs := env.listMessages(t, username)
	return len(msgs)
}

func (env *testEnv) listMessages(t *testing.T, username string) []msgstore.MessageInfo {
	t.Helper()
	cfg := msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: env.mailDir,
		Options: map[string]string{
			"maildir_subdir": "Maildir",
			"path_template":  "{localpart}",
		},
	}
	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("open verification store: %v", err)
	}
	msgs, err := store.List(context.Background(), username)
	if err != nil {
		t.Fatalf("list mailbox %s: %v", username, err)
	}
	return msgs
}

func (env *testEnv) retrieveMessage(t *testing.T, username, uid string) string {
	t.Helper()
	cfg := msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: env.mailDir,
		Options: map[string]string{
			"maildir_subdir": "Maildir",
			"path_template":  "{localpart}",
		},
	}
	store, err := msgstore.Open(cfg)
	if err != nil {
		t.Fatalf("open verification store: %v", err)
	}
	rc, err := store.Retrieve(context.Background(), username, uid)
	if err != nil {
		t.Fatalf("retrieve message %s/%s: %v", username, uid, err)
	}
	defer func() { _ = rc.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// smtpClient is a thin raw-TCP SMTP driver for integration tests.
type smtpClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialSMTP(t *testing.T, addr string) *smtpClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &smtpClient{conn: conn, r: bufio.NewReader(conn)}
}

// readResponse reads a potentially multi-line SMTP response and returns
// the numeric code and the concatenated message text.
func (c *smtpClient) readResponse(t *testing.T) (int, string) {
	t.Helper()
	var code int
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			t.Fatalf("response too short: %q", line)
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			t.Fatalf("parse response code from %q: %v", line, err)
		}
		code = n
		if len(line) > 4 {
			lines = append(lines, line[4:])
		}
		// A space after the code means this is the final line.
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}
	return code, strings.Join(lines, "\n")
}

func (c *smtpClient) send(t *testing.T, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(c.conn, "%s\r\n", line); err != nil {
		t.Fatalf("send %q: %v", line, err)
	}
}

// mustCode sends cmd and asserts the response code. Returns the response text.
// Pass cmd="" to just read a response without sending (e.g. for the greeting).
func (c *smtpClient) mustCode(t *testing.T, cmd string, wantCode int) string {
	t.Helper()
	if cmd != "" {
		c.send(t, cmd)
	}
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("%q → expected %d, got %d (%s)", cmd, wantCode, code, msg)
	}
	return msg
}

func (c *smtpClient) Greeting(t *testing.T) string {
	return c.mustCode(t, "", 220)
}

func (c *smtpClient) Ehlo(t *testing.T) string {
	return c.mustCode(t, "EHLO localhost", 250)
}

func (c *smtpClient) Quit(t *testing.T) {
	c.mustCode(t, "QUIT", 221)
	_ = c.conn.Close()
}

func (c *smtpClient) Rset(t *testing.T) {
	c.mustCode(t, "RSET", 250)
}

// StartTLS sends STARTTLS and upgrades the connection to TLS.
// Must be called after EHLO. Re-issues EHLO after the upgrade.
func (c *smtpClient) StartTLS(t *testing.T, cfg *tls.Config) {
	t.Helper()
	c.mustCode(t, "STARTTLS", 220)
	tlsConn := tls.Client(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
	// Re-issue EHLO on the upgraded connection.
	c.Ehlo(t)
}

// AuthPlain sends AUTH PLAIN with base64-encoded credentials.
func (c *smtpClient) AuthPlain(t *testing.T, username, password string) {
	t.Helper()
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	c.mustCode(t, "AUTH PLAIN "+creds, 235)
}

// SendMessage executes a full MAIL FROM / RCPT TO / DATA transaction.
func (c *smtpClient) SendMessage(t *testing.T, from, to, subject, body string) {
	t.Helper()
	c.mustCode(t, fmt.Sprintf("MAIL FROM:<%s>", from), 250)
	c.mustCode(t, fmt.Sprintf("RCPT TO:<%s>", to), 250)
	c.mustCode(t, "DATA", 354)
	msg := "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n\r\n" + body
	if _, err := fmt.Fprintf(c.conn, "%s\r\n.\r\n", msg); err != nil {
		t.Fatalf("write DATA body: %v", err)
	}
	code, resp := c.readResponse(t)
	if code != 250 {
		t.Fatalf("DATA end: expected 250, got %d (%s)", code, resp)
	}
}

// RcptExpect sends RCPT TO and asserts the given response code.
func (c *smtpClient) RcptExpect(t *testing.T, to string, wantCode int) {
	t.Helper()
	c.send(t, fmt.Sprintf("RCPT TO:<%s>", to))
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("RCPT TO <%s>: expected %d, got %d (%s)", to, wantCode, code, msg)
	}
}

// MailExpect sends MAIL FROM and asserts the given response code.
func (c *smtpClient) MailExpect(t *testing.T, from string, wantCode int) {
	t.Helper()
	c.send(t, fmt.Sprintf("MAIL FROM:<%s>", from))
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("MAIL FROM <%s>: expected %d, got %d (%s)", from, wantCode, code, msg)
	}
}

// containsFile reports whether any file exists under dir matching predicate.
func containsFile(t *testing.T, dir string, pred func(path string) bool) bool {
	t.Helper()
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if pred(path) {
			found = true
		}
		return nil
	})
	return found
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestRoundTrip_SMTP_Greeting(t *testing.T) {
	env := newTestEnv(t)
	c := dialSMTP(t, env.addr)
	greeting := c.Greeting(t)
	if !strings.Contains(greeting, "test.local") {
		t.Errorf("greeting %q does not contain hostname", greeting)
	}
}

func TestRoundTrip_SMTP_Ehlo(t *testing.T) {
	env := newTestEnv(t)
	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	ehlo := c.Ehlo(t)
	if ehlo == "" {
		t.Error("EHLO response empty")
	}
}

func TestRoundTrip_SMTP_Quit_BeforeDelivery(t *testing.T) {
	env := newTestEnv(t)
	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.Quit(t)
}

func TestRoundTrip_SMTP_Delivery_Basic(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Hello", "Test body.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 1 {
		t.Errorf("expected 1 message in alice's mailbox, got %d", got)
	}
}

// TestRoundTrip_SMTP_MaildirAtAbsolutePath is the key regression test for the
// absolute base_path bug. It verifies that delivered mail is written under
// mailDir (the writable data mount) and NOT under configDir (the read-only
// config mount). Without the filepath.IsAbs fix in auth/domain/filesystem.go,
// base_path would be joined with the domain config directory and mail would
// land (or fail to land) under configDir.
func TestRoundTrip_SMTP_MaildirAtAbsolutePath(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Regression", "Body.")
	c.Quit(t)

	// Mail must appear under mailDir.
	if !containsFile(t, env.mailDir, func(p string) bool { return true }) {
		t.Error("no files found under mailDir after delivery")
	}

	// Mail must NOT appear under configDir.
	if containsFile(t, env.configDir, func(p string) bool {
		// Ignore the config and passwd files we wrote ourselves.
		base := filepath.Base(p)
		return base != "config.toml" && base != "passwd"
	}) {
		t.Error("unexpected file found under configDir after delivery — base_path bug")
	}
}

func TestRoundTrip_SMTP_MessageContent_Preserved(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "bob", "testpass")

	wantSubject := "Content preservation test"
	wantBody := "The quick brown fox jumps over the lazy dog."

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "bob@test.local", wantSubject, wantBody)
	c.Quit(t)

	msgs := env.listMessages(t, "bob")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	content := env.retrieveMessage(t, "bob", msgs[0].UID)
	if !strings.Contains(content, wantSubject) {
		t.Errorf("message missing subject %q; got:\n%s", wantSubject, content)
	}
	if !strings.Contains(content, wantBody) {
		t.Errorf("message missing body %q; got:\n%s", wantBody, content)
	}
}

func TestRoundTrip_SMTP_UnknownDomain_Rejected(t *testing.T) {
	env := newTestEnv(t)

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.MailExpect(t, "sender@example.com", 250)
	c.RcptExpect(t, "alice@unknown.domain", 550)
}

func TestRoundTrip_SMTP_UnknownUser_Rejected(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.MailExpect(t, "sender@example.com", 250)
	c.RcptExpect(t, "nobody@test.local", 550)
}

func TestRoundTrip_SMTP_MultipleRcpt_Rejected(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.addUser(t, "bob", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.MailExpect(t, "sender@example.com", 250)
	c.RcptExpect(t, "alice@test.local", 250)
	c.RcptExpect(t, "bob@test.local", 452) // second recipient rejected
}

func TestRoundTrip_SMTP_AuthPlain_Success(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "s3cret")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.StartTLS(t, env.clientTLS)
	c.AuthPlain(t, "alice@test.local", "s3cret")
}

func TestRoundTrip_SMTP_AuthPlain_WrongPassword(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "rightpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.StartTLS(t, env.clientTLS)

	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice@test.local\x00wrongpass"))
	c.send(t, "AUTH PLAIN "+creds)
	code, _ := c.readResponse(t)
	if code != 535 {
		t.Errorf("expected 535 for wrong password, got %d", code)
	}
}

func TestRoundTrip_SMTP_AuthPlain_UnknownUser(t *testing.T) {
	env := newTestEnv(t)

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.StartTLS(t, env.clientTLS)

	creds := base64.StdEncoding.EncodeToString([]byte("\x00nobody@test.local\x00pass"))
	c.send(t, "AUTH PLAIN "+creds)
	code, _ := c.readResponse(t)
	if code != 535 {
		t.Errorf("expected 535 for unknown user, got %d", code)
	}
}

func TestRoundTrip_SMTP_AuthenticatedDelivery(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.StartTLS(t, env.clientTLS)
	c.AuthPlain(t, "alice@test.local", "testpass")
	c.SendMessage(t, "alice@test.local", "alice@test.local", "Self-send", "Hi me.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 1 {
		t.Errorf("expected 1 message after authenticated delivery, got %d", got)
	}
}

func TestRoundTrip_SMTP_Reset_ClearsEnvelope(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)

	// Start a transaction then reset.
	c.MailExpect(t, "sender@example.com", 250)
	c.RcptExpect(t, "alice@test.local", 250)
	c.Rset(t)

	// After RSET, start a fresh transaction and deliver.
	c.SendMessage(t, "sender@example.com", "alice@test.local", "After RSET", "Body.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 1 {
		t.Errorf("expected 1 message (only the one after RSET), got %d", got)
	}
}

func TestRoundTrip_SMTP_MultipleMessages_SameSession(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Message 1", "First.")
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Message 2", "Second.")
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Message 3", "Third.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 3 {
		t.Errorf("expected 3 messages, got %d", got)
	}
}

func TestRoundTrip_SMTP_EmptyFrom_Bounce(t *testing.T) {
	// MAIL FROM:<> is used for bounce messages (DSNs). The server must accept it.
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "", "alice@test.local", "Bounce", "Delivery status notification.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 1 {
		t.Errorf("expected 1 bounce message, got %d", got)
	}
}

func TestRoundTrip_SMTP_DomainIsolation(t *testing.T) {
	// Set up two domains: test.local and other.local.
	// Mail delivered to alice@test.local must not appear in other.local's maildir.
	env := newTestEnv(t) // test.local
	env.addUser(t, "alice", "testpass")

	// Create a second domain directory manually.
	otherDomain := "other.local"
	otherConfigDir := filepath.Join(env.configDir, otherDomain)
	if err := os.MkdirAll(filepath.Join(otherConfigDir, "keys"), 0755); err != nil {
		t.Fatalf("mkdir other domain: %v", err)
	}
	otherMailDir := t.TempDir()
	otherConfig := fmt.Sprintf(`[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = %q

[msgstore.options]
maildir_subdir = "Maildir"
path_template = "{localpart}"
`, otherMailDir)
	if err := os.WriteFile(filepath.Join(otherConfigDir, "config.toml"), []byte(otherConfig), 0644); err != nil {
		t.Fatalf("write other config.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(otherConfigDir, "passwd"), []byte(""), 0644); err != nil {
		t.Fatalf("write other passwd: %v", err)
	}

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "sender@example.com", "alice@test.local", "Isolated", "Body.")
	c.Quit(t)

	if got := env.countMessages(t, "alice"); got != 1 {
		t.Errorf("test.local: expected 1 message, got %d", got)
	}

	// Nothing should have been written to otherMailDir.
	if containsFile(t, otherMailDir, func(string) bool { return true }) {
		t.Error("domain isolation violation: file found in other.local mailDir")
	}
}

func TestRoundTrip_SMTP_NoDeliveryAgent_Rejected(t *testing.T) {
	// A server with no domain provider and no delivery agent must reject all mail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:      "test.local",
		MaxRecipients: 10,
	})
	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
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
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	c := dialSMTP(t, addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.MailExpect(t, "sender@example.com", 250)

	// With no domain provider, RCPT TO is accepted (no domain validation).
	// With no delivery agent, DATA must fail with 5xx.
	c.send(t, "RCPT TO:<anyone@anywhere.com>")
	code, _ := c.readResponse(t)
	if code != 250 {
		// Domain validation skipped when no provider configured — that's fine.
		// The test is about the DATA rejection below.
		t.Logf("RCPT TO without domain provider: %d", code)
		return
	}
	c.send(t, "DATA")
	code, _ = c.readResponse(t)
	if code != 354 {
		t.Logf("DATA not accepted (code %d), skipping DATA end check", code)
		return
	}
	if _, err := fmt.Fprintf(c.conn, "Subject: Test\r\n\r\nBody\r\n.\r\n"); err != nil {
		t.Fatalf("write data: %v", err)
	}
	code, msg := c.readResponse(t)
	if code/100 != 5 {
		t.Errorf("expected 5xx for delivery with no agent, got %d (%s)", code, msg)
	}
}
