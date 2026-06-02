package smtp_test

import (
	"bufio"
	"bytes"
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
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
	"google.golang.org/grpc"
)

// mockDeliveryServer implements DeliveryServiceServer for roundtrip tests.
type mockDeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer

	mu       sync.Mutex
	messages []capturedMessage
}

type capturedMessage struct {
	metadata *pb.DeliverMetadata
	body     []byte
}

func (s *mockDeliveryServer) Deliver(stream grpc.ClientStreamingServer[pb.DeliverRequest, pb.DeliverResponse]) error {
	var meta *pb.DeliverMetadata
	var body bytes.Buffer

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch p := req.Payload.(type) {
		case *pb.DeliverRequest_Metadata:
			meta = p.Metadata
		case *pb.DeliverRequest_Data:
			body.Write(p.Data)
		}
	}

	s.mu.Lock()
	s.messages = append(s.messages, capturedMessage{metadata: meta, body: body.Bytes()})
	s.mu.Unlock()

	return stream.SendAndClose(&pb.DeliverResponse{
		Result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
	})
}

func (s *mockDeliveryServer) countMessages() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *mockDeliveryServer) getMessage(i int) capturedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.messages[i]
}

// mockSessionServer implements SessionServiceServer for roundtrip tests.
type mockSessionServer struct {
	smpb.UnimplementedSessionServiceServer

	// users maps user@domain to password for Login.
	users map[string]string
	// localDomains is the set of domains considered local.
	localDomains map[string]bool
}

func (s *mockSessionServer) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	pass, ok := s.users[req.Username]
	if !ok || pass != req.Password {
		return nil, fmt.Errorf("authentication failed")
	}
	return &smpb.LoginResponse{
		SessionToken: "test-token",
		Mailbox:      req.Username,
	}, nil
}

func (s *mockSessionServer) ValidateRecipient(_ context.Context, req *smpb.ValidateRecipientRequest) (*smpb.ValidateRecipientResponse, error) {
	addr := req.Address
	// Extract domain
	domain := ""
	if idx := strings.LastIndex(addr, "@"); idx >= 0 {
		domain = strings.ToLower(addr[idx+1:])
	}

	if !s.localDomains[domain] {
		return &smpb.ValidateRecipientResponse{
			DomainIsLocal: false,
		}, nil
	}

	// For test purposes, all users in local domains exist.
	return &smpb.ValidateRecipientResponse{
		DomainIsLocal: true,
		UserExists:    true,
	}, nil
}

// testEnv holds the infrastructure for a round-trip SMTP integration test.
type testEnv struct {
	addr           string
	domain         string
	clientTLS      *tls.Config
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	deliveryServer *mockDeliveryServer
	sessionServer  *mockSessionServer
}

// generateTestTLS generates a self-signed ECDSA certificate for testing.
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

	domainName := "test.local"

	deliverySrv := &mockDeliveryServer{}
	sessionSrv := &mockSessionServer{
		users:        map[string]string{},
		localDomains: map[string]bool{domainName: true},
	}

	// Start mock gRPC server for session-manager.
	socketPath := t.TempDir() + "/sm.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, deliverySrv)
	smpb.RegisterSessionServiceServer(gsrv, sessionSrv)
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	smDelivery, err := smtpserver.NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerDeliveryAgent: %v", err)
	}
	t.Cleanup(func() { _ = smDelivery.Close() })

	serverTLS, clientTLS := generateTestTLS(t)

	// Pre-allocate a port.
	smtpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := smtpLn.Addr().String()
	if err := smtpLn.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:       "test.local",
		SMDelivery:     smDelivery,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
		TempDir:        t.TempDir(),
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
		addr:           addr,
		domain:         domainName,
		clientTLS:      clientTLS,
		cancel:         cancel,
		deliveryServer: deliverySrv,
		sessionServer:  sessionSrv,
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

func (env *testEnv) addUser(t *testing.T, username, password string) {
	t.Helper()
	fullAddr := username + "@" + env.domain
	env.sessionServer.users[fullAddr] = password
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

func (c *smtpClient) mustCode(t *testing.T, cmd string, wantCode int) string {
	t.Helper()
	if cmd != "" {
		c.send(t, cmd)
	}
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("%q -> expected %d, got %d (%s)", cmd, wantCode, code, msg)
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

func (c *smtpClient) StartTLS(t *testing.T, cfg *tls.Config) {
	t.Helper()
	c.mustCode(t, "STARTTLS", 220)
	tlsConn := tls.Client(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
	c.Ehlo(t)
}

func (c *smtpClient) AuthPlain(t *testing.T, username, password string) {
	t.Helper()
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	c.mustCode(t, "AUTH PLAIN "+creds, 235)
}

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

func (c *smtpClient) RcptExpect(t *testing.T, to string, wantCode int) {
	t.Helper()
	c.send(t, fmt.Sprintf("RCPT TO:<%s>", to))
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("RCPT TO <%s>: expected %d, got %d (%s)", to, wantCode, code, msg)
	}
}

func (c *smtpClient) MailExpect(t *testing.T, from string, wantCode int) {
	t.Helper()
	c.send(t, fmt.Sprintf("MAIL FROM:<%s>", from))
	code, msg := c.readResponse(t)
	if code != wantCode {
		t.Fatalf("MAIL FROM <%s>: expected %d, got %d (%s)", from, wantCode, code, msg)
	}
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

	if got := env.deliveryServer.countMessages(); got != 1 {
		t.Errorf("expected 1 delivered message, got %d", got)
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

	if env.deliveryServer.countMessages() != 1 {
		t.Fatalf("expected 1 message, got %d", env.deliveryServer.countMessages())
	}
	msg := env.deliveryServer.getMessage(0)
	content := string(msg.body)
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
	// Session-manager returns a generic gRPC error for failed auth, which maps to 454 (temp fail).
	if code != 454 {
		t.Errorf("expected 454 for wrong password, got %d", code)
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

	if got := env.deliveryServer.countMessages(); got != 1 {
		t.Errorf("expected 1 message after authenticated delivery, got %d", got)
	}
}

func TestRoundTrip_SMTP_Reset_ClearsEnvelope(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)

	c.MailExpect(t, "sender@example.com", 250)
	c.RcptExpect(t, "alice@test.local", 250)
	c.Rset(t)

	c.SendMessage(t, "sender@example.com", "alice@test.local", "After RSET", "Body.")
	c.Quit(t)

	if got := env.deliveryServer.countMessages(); got != 1 {
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

	if got := env.deliveryServer.countMessages(); got != 3 {
		t.Errorf("expected 3 messages, got %d", got)
	}
}

func TestRoundTrip_SMTP_EmptyFrom_Bounce(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "alice", "testpass")

	c := dialSMTP(t, env.addr)
	c.Greeting(t)
	c.Ehlo(t)
	c.SendMessage(t, "", "alice@test.local", "Bounce", "Delivery status notification.")
	c.Quit(t)

	if got := env.deliveryServer.countMessages(); got != 1 {
		t.Errorf("expected 1 bounce message, got %d", got)
	}
}

func TestRoundTrip_SMTP_NoDeliveryAgent_Rejected(t *testing.T) {
	// A server with no session-manager must reject at DATA time.
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

	// With no session-manager, RCPT TO is accepted (no domain validation).
	c.send(t, "RCPT TO:<anyone@anywhere.com>")
	code, _ := c.readResponse(t)
	if code != 250 {
		t.Logf("RCPT TO without session-manager: %d", code)
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
	if code/100 != 4 {
		t.Errorf("expected 4xx for delivery with no agent, got %d (%s)", code, msg)
	}
}
