// Package pop3_test contains round-trip integration tests for the POP3 server.
//
// These tests wire the full stack — filesystem domain provider, passwd auth agent,
// maildir message store, and POP3 protocol handler — and exercise the protocol
// over a real TLS connection.
//
// Key regression covered: TestRoundTrip_MaildirCreatedAtAbsolutePath verifies that
// an absolute base_path in a domain config.toml is used verbatim and not re-joined
// with the domain config directory. The production bug (auth module predating the
// filepath.IsAbs fix) caused writes to land in the read-only /etc config mount
// instead of the writable /opt data mount.
package pop3_test

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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	authdomain "github.com/infodancer/maildancer/auth/domain"
	_ "github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

// testEnv holds all the pieces needed to run a round-trip integration test.
// The directory layout deliberately mirrors production:
//
//	configDir/   ← simulates read-only /etc/infodancer/domains (domain config)
//	  test.local/
//	    config.toml
//	    passwd
//	    keys/
//	mailDir/     ← simulates writable /opt/infodancer/domains (mail data)
//	  alice/Maildir/{cur,new,tmp}
//	  bob/Maildir/{cur,new,tmp}
//
// The domain config.toml specifies base_path as the absolute path to mailDir.
// This separation is what the production bug violated.
type testEnv struct {
	addr      string            // "127.0.0.1:PORT" of the POP3S listener
	configDir string            // domains root (simulates /etc/infodancer/domains)
	mailDir   string            // mail storage root (simulates /opt/infodancer/domains/users)
	domain    string            // test domain name
	store     msgstore.MsgStore // pre-opened store for delivering test messages
	clientTLS *tls.Config       // client TLS config for test connections

	ln     net.Listener
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// newTestEnv starts a full POP3S server backed by real filesystem auth and maildir
// storage. The server listens on a random localhost port. t.Cleanup handles teardown.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()

	// configDir is the domain config root — read-only in production (/etc mount).
	configDir := filepath.Join(dir, "config", "domains")
	// mailDir is the mail data root — writable in production (/opt mount).
	mailDir := filepath.Join(dir, "mail", "users")

	const domainName = "test.local"
	domainConfigDir := filepath.Join(configDir, domainName)

	for _, d := range []string{
		domainConfigDir,
		filepath.Join(domainConfigDir, "keys"),
		mailDir,
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Write domain config.toml with an ABSOLUTE base_path pointing into mailDir.
	// The critical invariant: mailDir is completely separate from domainConfigDir.
	// If the auth module incorrectly joins an absolute path with domainConfigDir,
	// the Maildir will be created inside the config tree instead of here.
	configTOML := fmt.Sprintf(`[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = %q

[msgstore.options]
maildir_subdir = "Maildir"
`, mailDir)
	if err := os.WriteFile(filepath.Join(domainConfigDir, "config.toml"), []byte(configTOML), 0644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	// Create an empty passwd file (users are added via env.addUser).
	passwdPath := filepath.Join(domainConfigDir, "passwd")
	if f, err := os.Create(passwdPath); err != nil {
		t.Fatalf("create passwd: %v", err)
	} else {
		_ = f.Close()
	}

	serverTLS, clientTLS := generateTestTLS(t)

	// Wire the domain provider and auth router.
	logger := logging.NewLogger("error")
	domainProvider := authdomain.NewFilesystemDomainProvider(configDir, logger)
	authRouter := authdomain.NewAuthRouter(domainProvider, nil)

	// Open a local store for delivering messages in test setup. This uses the
	// same configuration as the domain provider's store so paths match.
	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     "maildir",
		BasePath: mailDir,
		Options:  map[string]string{"maildir_subdir": "Maildir"},
	})
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}

	handler := pop3.Handler("mail.test.local", authRouter, nil, serverTLS, &metrics.NoopCollector{})

	// Bind on a random localhost port.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	env := &testEnv{
		addr:      ln.Addr().String(),
		configDir: configDir,
		mailDir:   mailDir,
		domain:    domainName,
		store:     store,
		clientTLS: clientTLS,
		ln:        ln,
		cancel:    cancel,
	}

	// Accept loop: hand each incoming connection to the POP3 handler.
	env.wg.Add(1)
	go func() {
		defer env.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			env.wg.Add(1)
			go func(c net.Conn) {
				defer env.wg.Done()
				connLogger := logging.NewLogger("error")
				srvConn := server.NewConnection(c, server.ConnectionConfig{
					IdleTimeout:    30 * time.Second,
					CommandTimeout: 10 * time.Second,
					Logger:         connLogger,
				})
				connCtx := logging.NewContext(ctx, connLogger)
				handler(connCtx, srvConn)
			}(conn)
		}
	}()

	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		env.wg.Wait()
	})

	return env
}

// addUser adds a user to the domain's passwd file.
// Must be called before the first connection (domain is cached after first auth).
func (e *testEnv) addUser(t *testing.T, username, password string) {
	t.Helper()
	passwdPath := filepath.Join(e.configDir, e.domain, "passwd")
	if err := passwd.AddUser(passwdPath, username, password); err != nil {
		t.Fatalf("addUser(%s): %v", username, err)
	}
}

// deliverMessage places a test message in the specified mailbox via the store.
func (e *testEnv) deliverMessage(t *testing.T, mailbox, subject, body string) {
	t.Helper()
	msg := fmt.Sprintf(
		"From: sender@test.local\r\nTo: %s@%s\r\nSubject: %s\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n%s\r\n",
		mailbox, e.domain, subject, body,
	)
	env := msgstore.Envelope{Recipients: []string{mailbox}}
	if err := e.store.Deliver(context.Background(), env, strings.NewReader(msg)); err != nil {
		t.Fatalf("deliverMessage(%s): %v", mailbox, err)
	}
}

// dial opens a TLS connection to the test server and wraps it in a pop3TestClient.
func (e *testEnv) dial(t *testing.T) *pop3TestClient {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		e.addr,
		e.clientTLS,
	)
	if err != nil {
		t.Fatalf("dial %s: %v", e.addr, err)
	}
	c := &pop3TestClient{conn: conn, r: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	return c
}

// generateTestTLS creates a self-signed ECDSA certificate valid for 127.0.0.1.
// Returns server config (with certificate) and client config (trusting that cert).
func generateTestTLS(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pop3d-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse key pair: %v", err)
	}

	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool.AddCert(parsed)
	clientTLS = &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}

	return serverTLS, clientTLS
}

// pop3TestClient is a thin POP3 protocol driver for integration tests.
type pop3TestClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *pop3TestClient) readLine() string {
	line, _ := c.r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// readMultiLine reads lines until the POP3 "." terminator, de-dot-stuffing as it goes.
func (c *pop3TestClient) readMultiLine(t *testing.T) []string {
	t.Helper()
	var lines []string
	for {
		line := c.readLine()
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		lines = append(lines, line)
	}
	return lines
}

func (c *pop3TestClient) send(t *testing.T, cmd string) {
	t.Helper()
	if _, err := fmt.Fprintf(c.conn, "%s\r\n", cmd); err != nil {
		t.Fatalf("send %q: %v", cmd, err)
	}
}

// mustOK asserts +OK and returns the message text.
func (c *pop3TestClient) mustOK(t *testing.T) string {
	t.Helper()
	line := c.readLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Fatalf("expected +OK, got: %q", line)
	}
	msg := strings.TrimPrefix(line, "+OK")
	return strings.TrimLeft(msg, " ")
}

// mustErr asserts -ERR and returns the error text.
func (c *pop3TestClient) mustErr(t *testing.T) string {
	t.Helper()
	line := c.readLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Fatalf("expected -ERR, got: %q", line)
	}
	msg := strings.TrimPrefix(line, "-ERR")
	return strings.TrimLeft(msg, " ")
}

// Greet reads the server greeting.
func (c *pop3TestClient) Greet(t *testing.T) string {
	t.Helper()
	return c.mustOK(t)
}

// Auth performs USER/PASS authentication.
func (c *pop3TestClient) Auth(t *testing.T, user, pass string) {
	t.Helper()
	c.send(t, "USER "+user)
	c.mustOK(t)
	c.send(t, "PASS "+pass)
	c.mustOK(t)
}

// AuthExpectFail performs USER/PASS and expects -ERR on PASS.
func (c *pop3TestClient) AuthExpectFail(t *testing.T, user, pass string) string {
	t.Helper()
	c.send(t, "USER "+user)
	// USER may succeed or fail depending on whether the user exists at that point
	c.readLine() // consume USER response
	c.send(t, "PASS "+pass)
	return c.mustErr(t)
}

// AuthPlain authenticates using AUTH PLAIN with inline credentials.
func (c *pop3TestClient) AuthPlain(t *testing.T, user, pass string) {
	t.Helper()
	// SASL PLAIN: \0authcid\0passwd (no authzid)
	token := "\x00" + user + "\x00" + pass
	encoded := base64.StdEncoding.EncodeToString([]byte(token))
	c.send(t, "AUTH PLAIN "+encoded)
	c.mustOK(t)
}

// Stat executes STAT and returns (count, totalBytes).
func (c *pop3TestClient) Stat(t *testing.T) (count, size int) {
	t.Helper()
	c.send(t, "STAT")
	resp := c.mustOK(t)
	parts := strings.Fields(resp)
	if len(parts) < 2 {
		t.Fatalf("STAT response malformed: %q", resp)
	}
	count, _ = strconv.Atoi(parts[0])
	size, _ = strconv.Atoi(parts[1])
	return count, size
}

// List executes LIST and returns the scan-line entries (e.g., ["1 512", "2 1024"]).
func (c *pop3TestClient) List(t *testing.T) []string {
	t.Helper()
	c.send(t, "LIST")
	c.mustOK(t)
	return c.readMultiLine(t)
}

// Retr retrieves message n and returns its content.
func (c *pop3TestClient) Retr(t *testing.T, n int) string {
	t.Helper()
	c.send(t, fmt.Sprintf("RETR %d", n))
	c.mustOK(t)
	return strings.Join(c.readMultiLine(t), "\r\n")
}

// Dele marks message n for deletion.
func (c *pop3TestClient) Dele(t *testing.T, n int) {
	t.Helper()
	c.send(t, fmt.Sprintf("DELE %d", n))
	c.mustOK(t)
}

// Rset cancels all pending deletions.
func (c *pop3TestClient) Rset(t *testing.T) {
	t.Helper()
	c.send(t, "RSET")
	c.mustOK(t)
}

// Uidl executes UIDL and returns the entries.
func (c *pop3TestClient) Uidl(t *testing.T) []string {
	t.Helper()
	c.send(t, "UIDL")
	c.mustOK(t)
	return c.readMultiLine(t)
}

// Top executes "TOP n lines" and returns the content.
func (c *pop3TestClient) Top(t *testing.T, msg, lines int) string {
	t.Helper()
	c.send(t, fmt.Sprintf("TOP %d %d", msg, lines))
	c.mustOK(t)
	return strings.Join(c.readMultiLine(t), "\r\n")
}

// Noop executes NOOP.
func (c *pop3TestClient) Noop(t *testing.T) {
	t.Helper()
	c.send(t, "NOOP")
	c.mustOK(t)
}

// Capa requests the server capabilities.
func (c *pop3TestClient) Capa(t *testing.T) []string {
	t.Helper()
	c.send(t, "CAPA")
	c.mustOK(t)
	return c.readMultiLine(t)
}

// Quit sends QUIT.
func (c *pop3TestClient) Quit(t *testing.T) {
	t.Helper()
	c.send(t, "QUIT")
	c.mustOK(t)
}

// --- Integration Tests ---

func TestRoundTrip_Greeting(t *testing.T) {
	env := newTestEnv(t)
	c := env.dial(t)
	greeting := c.Greet(t)
	if !strings.Contains(greeting, "POP3") {
		t.Errorf("greeting does not mention POP3: %q", greeting)
	}
}

func TestRoundTrip_Capa_BeforeAuth(t *testing.T) {
	env := newTestEnv(t)
	c := env.dial(t)
	c.Greet(t)

	caps := c.Capa(t)
	capSet := make(map[string]bool)
	for _, cap := range caps {
		capSet[cap] = true
	}

	for _, want := range []string{"TOP", "UIDL"} {
		if !capSet[want] {
			t.Errorf("CAPA missing %q; caps: %v", want, caps)
		}
	}
	// POP3S connection is already TLS, so USER and SASL PLAIN should be advertised.
	if !capSet["USER"] {
		t.Errorf("CAPA missing USER on TLS connection; caps: %v", caps)
	}
}

func TestRoundTrip_AuthUserPass_Success(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	// STAT proves we entered TRANSACTION state.
	count, size := c.Stat(t)
	if count != 0 || size != 0 {
		t.Errorf("new user: expected STAT 0 0, got %d %d", count, size)
	}
	c.Quit(t)
}

// TestRoundTrip_MaildirCreatedAtAbsolutePath is the primary regression test for
// the production bug where the auth module joined an absolute base_path with the
// domain config directory instead of using it verbatim.
//
// Production symptom: "mkdir /etc/infodancer/domains/triggerfinger.blog/opt: read-only
// file system" because /etc was a read-only config mount and the path was being
// constructed as configDir + absoluteDataPath instead of just absoluteDataPath.
//
// The test verifies:
//  1. Maildir is created under mailDir (the absolute path in config.toml).
//  2. Maildir is NOT created anywhere under configDir.
func TestRoundTrip_MaildirCreatedAtAbsolutePath(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")
	c.Quit(t)

	// The Maildir MUST be at the correct absolute path.
	wantMaildir := filepath.Join(env.mailDir, "alice", "Maildir")
	if _, err := os.Stat(wantMaildir); os.IsNotExist(err) {
		t.Errorf("Maildir not created at expected absolute path %q", wantMaildir)
	}

	// The Maildir MUST NOT have been created under the domain config directory.
	// The buggy path would be: configDir/test.local/<tail of absolute path>
	domainDir := filepath.Join(env.configDir, env.domain)
	entries, err := os.ReadDir(domainDir)
	if err != nil {
		t.Fatalf("read domain dir: %v", err)
	}
	unexpected := map[string]bool{"opt": true, "users": true, "Maildir": true, "alice": true}
	for _, e := range entries {
		if unexpected[e.Name()] {
			t.Errorf("unexpected entry %q in domain config dir (basePath bug): entries=%v",
				e.Name(), entries)
		}
	}
}

func TestRoundTrip_AuthUserPass_WrongPassword(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "correctpass")

	c := env.dial(t)
	c.Greet(t)
	c.send(t, "USER alice@test.local")
	c.mustOK(t)
	c.send(t, "PASS wrongpass")
	c.mustErr(t)
}

func TestRoundTrip_AuthUserPass_UnknownUser(t *testing.T) {
	env := newTestEnv(t)

	c := env.dial(t)
	c.Greet(t)
	c.send(t, "USER nobody@test.local")
	c.mustOK(t)
	c.send(t, "PASS anypass")
	c.mustErr(t)
}

func TestRoundTrip_AuthUserPass_UnknownDomain(t *testing.T) {
	env := newTestEnv(t)

	c := env.dial(t)
	c.Greet(t)
	c.send(t, "USER alice@nosuchdomain.org")
	c.mustOK(t)
	c.send(t, "PASS anypass")
	c.mustErr(t)
}

func TestRoundTrip_AuthSASLPlain_Success(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.AuthPlain(t, "alice@test.local", "testpass")

	// Prove we're in TRANSACTION state.
	count, _ := c.Stat(t)
	if count != 0 {
		t.Errorf("STAT after SASL auth: expected 0, got %d", count)
	}
	c.Quit(t)
}

func TestRoundTrip_AuthSASLPlain_WrongPassword(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)

	token := "\x00alice@test.local\x00wrongpass"
	c.send(t, "AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte(token)))
	c.mustErr(t)
}

func TestRoundTrip_AuthSASLPlain_MultiStep(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)

	// Step 1: AUTH PLAIN with no inline credentials triggers a challenge.
	c.send(t, "AUTH PLAIN")
	line := c.readLine()
	if !strings.HasPrefix(line, "+ ") {
		t.Fatalf("expected challenge (+ ...), got: %q", line)
	}

	// Step 2: send credentials.
	token := "\x00alice@test.local\x00testpass"
	c.send(t, base64.StdEncoding.EncodeToString([]byte(token)))
	c.mustOK(t)

	count, _ := c.Stat(t)
	if count != 0 {
		t.Errorf("STAT after multi-step SASL: expected 0, got %d", count)
	}
	c.Quit(t)
}

func TestRoundTrip_CommandsRequireAuth(t *testing.T) {
	env := newTestEnv(t)
	c := env.dial(t)
	c.Greet(t)

	// NOOP is allowed in AUTHORIZATION state (RFC 1939 does not restrict it)
	cmds := []string{"STAT", "LIST", "RETR 1", "DELE 1", "RSET", "UIDL", "TOP 1 0"}
	for _, cmd := range cmds {
		c.send(t, cmd)
		line := c.readLine()
		if !strings.HasPrefix(line, "-ERR") {
			t.Errorf("%q before auth: expected -ERR, got %q", cmd, line)
		}
	}
}

func TestRoundTrip_Stat_EmptyMailbox(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	count, size := c.Stat(t)
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
	if size != 0 {
		t.Errorf("size = %d, want 0", size)
	}
	c.Quit(t)
}

func TestRoundTrip_DeliverAndList(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "Hello", "World")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	count, _ := c.Stat(t)
	if count != 1 {
		t.Fatalf("STAT count = %d, want 1", count)
	}

	listings := c.List(t)
	if len(listings) != 1 {
		t.Errorf("LIST entries = %d, want 1", len(listings))
	}
	c.Quit(t)
}

func TestRoundTrip_DeliverAndRetrieve(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	const subject = "Round-Trip Subject"
	const body = "Round-trip body content."
	env.deliverMessage(t, "alice", subject, body)

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	count, _ := c.Stat(t)
	if count != 1 {
		t.Fatalf("expected 1 message, got %d", count)
	}

	content := c.Retr(t, 1)
	if !strings.Contains(content, "Subject: "+subject) {
		t.Errorf("retrieved message missing Subject header; got:\n%s", content)
	}
	if !strings.Contains(content, body) {
		t.Errorf("retrieved message missing body; got:\n%s", content)
	}
	c.Quit(t)
}

func TestRoundTrip_DeleteOnQuit_Expunges(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "Delete me", "bye")

	// Session 1: delete and quit.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")

		count, _ := c.Stat(t)
		if count != 1 {
			t.Fatalf("pre-delete: expected 1 message, got %d", count)
		}
		c.Dele(t, 1)
		c.Quit(t)
	}

	// Session 2: mailbox must be empty.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")

		count, _ := c.Stat(t)
		if count != 0 {
			t.Errorf("post-delete: expected 0 messages, got %d", count)
		}
		c.Quit(t)
	}
}

func TestRoundTrip_RsetUndoesDelete(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "Msg1", "body1")
	env.deliverMessage(t, "alice", "Msg2", "body2")

	// Session 1: delete first message, then RSET, then quit.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")
		c.Dele(t, 1)
		c.Rset(t) // cancels the delete
		c.Quit(t)
	}

	// Session 2: both messages should survive.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")

		count, _ := c.Stat(t)
		if count != 2 {
			t.Errorf("expected 2 messages after rset+quit, got %d", count)
		}
		c.Quit(t)
	}
}

func TestRoundTrip_MultiMessage_ListRetrUidl(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	const n = 5
	for i := 1; i <= n; i++ {
		env.deliverMessage(t, "alice", fmt.Sprintf("Subject %d", i), fmt.Sprintf("Body %d", i))
	}

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	count, _ := c.Stat(t)
	if count != n {
		t.Fatalf("STAT count = %d, want %d", count, n)
	}

	listings := c.List(t)
	if len(listings) != n {
		t.Errorf("LIST entries = %d, want %d", len(listings), n)
	}

	uidls := c.Uidl(t)
	if len(uidls) != n {
		t.Errorf("UIDL entries = %d, want %d", len(uidls), n)
	}

	// All UIDs must be unique.
	seen := make(map[string]bool)
	for _, entry := range uidls {
		parts := strings.Fields(entry)
		if len(parts) < 2 {
			t.Errorf("malformed UIDL entry: %q", entry)
			continue
		}
		uid := parts[1]
		if seen[uid] {
			t.Errorf("duplicate UID in UIDL: %s", uid)
		}
		seen[uid] = true
	}

	// Retrieve all messages and verify content.
	for i := 1; i <= n; i++ {
		content := c.Retr(t, i)
		// Note: message order from maildir is not guaranteed; just verify non-empty.
		if content == "" {
			t.Errorf("message %d: empty content", i)
		}
	}

	c.Quit(t)
}

func TestRoundTrip_ListSpecific(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "Msg1", "body1")
	env.deliverMessage(t, "alice", "Msg2", "body2")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	c.send(t, "LIST 1")
	resp := c.mustOK(t)
	parts := strings.Fields(resp)
	if len(parts) < 2 {
		t.Fatalf("LIST 1 response malformed: %q", resp)
	}
	if parts[0] != "1" {
		t.Errorf("LIST 1: msg number = %q, want 1", parts[0])
	}
	// Second field should be a positive size.
	size, _ := strconv.Atoi(parts[1])
	if size <= 0 {
		t.Errorf("LIST 1: size = %d, want > 0", size)
	}

	c.Quit(t)
}

func TestRoundTrip_UidlSpecific(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "Msg", "body")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	c.send(t, "UIDL 1")
	resp := c.mustOK(t)
	parts := strings.Fields(resp)
	if len(parts) < 2 {
		t.Fatalf("UIDL 1 response malformed: %q", resp)
	}
	if parts[0] != "1" {
		t.Errorf("UIDL 1: msg number = %q, want 1", parts[0])
	}
	if parts[1] == "" {
		t.Error("UIDL 1: empty UID")
	}

	c.Quit(t)
}

func TestRoundTrip_Top_HeadersOnly(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")
	env.deliverMessage(t, "alice", "TOP Test", "Line1\r\nLine2\r\nLine3")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	// TOP 1 0 returns only headers.
	top0 := c.Top(t, 1, 0)
	if !strings.Contains(top0, "Subject: TOP Test") {
		t.Errorf("TOP 1 0 missing Subject header; got:\n%s", top0)
	}
	if strings.Contains(top0, "Line1") {
		t.Errorf("TOP 1 0 must not include body lines; got:\n%s", top0)
	}

	c.Quit(t)
}

func TestRoundTrip_Noop(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")
	c.Noop(t)
	c.Noop(t) // double-NOOP to verify it stays in TRANSACTION
	count, _ := c.Stat(t)
	if count != 0 {
		t.Errorf("STAT after NOOP: expected 0, got %d", count)
	}
	c.Quit(t)
}

func TestRoundTrip_Quit_BeforeAuth(t *testing.T) {
	env := newTestEnv(t)
	c := env.dial(t)
	c.Greet(t)
	c.Quit(t)
}

func TestRoundTrip_DomainIsolation(t *testing.T) {
	// Two users in the same domain; each sees only their own messages.
	env := newTestEnv(t)
	env.addUser(t, "alice", "alicepass")
	env.addUser(t, "bob", "bobpass")

	env.deliverMessage(t, "alice", "For Alice", "alice-only content")
	env.deliverMessage(t, "bob", "For Bob", "bob-only content")

	// Alice's session.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "alicepass")

		count, _ := c.Stat(t)
		if count != 1 {
			t.Errorf("alice: expected 1 message, got %d", count)
		}
		content := c.Retr(t, 1)
		if !strings.Contains(content, "alice-only content") {
			t.Errorf("alice: wrong message content: %s", content)
		}
		if strings.Contains(content, "bob-only content") {
			t.Errorf("alice: got bob's message!")
		}
		c.Quit(t)
	}

	// Bob's session.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "bob@test.local", "bobpass")

		count, _ := c.Stat(t)
		if count != 1 {
			t.Errorf("bob: expected 1 message, got %d", count)
		}
		content := c.Retr(t, 1)
		if !strings.Contains(content, "bob-only content") {
			t.Errorf("bob: wrong message content: %s", content)
		}
		if strings.Contains(content, "alice-only content") {
			t.Errorf("bob: got alice's message!")
		}
		c.Quit(t)
	}
}

func TestRoundTrip_RetrNonExistent(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	c.send(t, "RETR 99")
	c.mustErr(t)
	c.Quit(t)
}

func TestRoundTrip_DeleNonExistent(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	c.send(t, "DELE 99")
	c.mustErr(t)
	c.Quit(t)
}

func TestRoundTrip_DeleHidesMessageInSession(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	env.deliverMessage(t, "alice", "Msg1", "body1")
	env.deliverMessage(t, "alice", "Msg2", "body2")
	env.deliverMessage(t, "alice", "Msg3", "body3")

	c := env.dial(t)
	c.Greet(t)
	c.Auth(t, "alice@test.local", "testpass")

	// Delete message 2.
	c.Dele(t, 2)

	// STAT should reflect 2 messages, not 3.
	count, _ := c.Stat(t)
	if count != 2 {
		t.Errorf("STAT after DELE 2: count = %d, want 2", count)
	}

	// LIST should not include entry "2 ...".
	listings := c.List(t)
	for _, l := range listings {
		if strings.HasPrefix(l, "2 ") {
			t.Errorf("LIST after DELE 2 still shows message 2: %q", l)
		}
	}

	c.Quit(t)
}

func TestRoundTrip_PersistentMailboxAcrossSessions(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	// Session 1: empty mailbox.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")
		count, _ := c.Stat(t)
		if count != 0 {
			t.Fatalf("session 1: expected 0, got %d", count)
		}
		c.Quit(t)
	}

	// Deliver a message after session 1 ended.
	env.deliverMessage(t, "alice", "Late Message", "arrived after first login")

	// Session 2: message should be visible.
	{
		c := env.dial(t)
		c.Greet(t)
		c.Auth(t, "alice@test.local", "testpass")
		count, _ := c.Stat(t)
		if count != 1 {
			t.Errorf("session 2: expected 1, got %d", count)
		}
		c.Quit(t)
	}
}
