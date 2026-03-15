// Package pop3_test contains round-trip integration tests for the POP3 server.
//
// These tests wire the full stack — mock session-manager gRPC server and POP3
// protocol handler — and exercise the protocol over a real TLS connection.
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/infodancer/maildancer/internal/pop3d/server"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// testEnv holds all the pieces needed to run a round-trip integration test.
// Authentication and mailbox operations are backed by a mock gRPC
// session-manager server.
type testEnv struct {
	addr      string       // "127.0.0.1:PORT" of the POP3S listener
	clientTLS *tls.Config  // client TLS config for test connections
	mockSM    *testSMState // shared state backing the mock session-manager

	ln     net.Listener
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// testSMState holds the in-memory state for the mock session-manager.
type testSMState struct {
	mu       sync.Mutex
	users    map[string]string          // username -> password
	messages map[string][]*testMessage  // username -> messages
	deleted  map[string]map[uint32]bool // username -> set of deleted UIDs
	nextUID  map[string]uint32          // username -> next UID to assign
}

type testMessage struct {
	uid  uint32
	data []byte
}

func newTestSMState() *testSMState {
	return &testSMState{
		users:    make(map[string]string),
		messages: make(map[string][]*testMessage),
		deleted:  make(map[string]map[uint32]bool),
		nextUID:  make(map[string]uint32),
	}
}

func (s *testSMState) addUser(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = password
	if _, ok := s.nextUID[username]; !ok {
		s.nextUID[username] = 1
	}
}

func (s *testSMState) deliverMessage(username, subject, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid := s.nextUID[username]
	s.nextUID[username] = uid + 1
	msg := fmt.Sprintf(
		"From: sender@test.local\r\nTo: %s\r\nSubject: %s\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n%s\r\n",
		username, subject, body,
	)
	s.messages[username] = append(s.messages[username], &testMessage{uid: uid, data: []byte(msg)})
}

// testSessionService implements the session-manager's SessionService.
type testSessionService struct {
	smpb.UnimplementedSessionServiceServer
	state *testSMState
}

func (s *testSessionService) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	pass, ok := s.state.users[req.Username]
	if !ok || pass != req.Password {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Session token is just the username for test purposes.
	return &smpb.LoginResponse{
		SessionToken: req.Username,
		Mailbox:      req.Username,
	}, nil
}

func (s *testSessionService) Logout(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	return &smpb.LogoutResponse{}, nil
}

// testMailboxService implements the mail-session's MailboxService.
type testMailboxService struct {
	pb.UnimplementedMailboxServiceServer
	state *testSMState
}

func (s *testMailboxService) tokenUser(ctx context.Context) string {
	// Extract session token from gRPC metadata (set by tokenCtx in smclient).
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		vals := md.Get("session-token")
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func (s *testMailboxService) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	user := s.tokenUser(ctx)
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	var msgs []*pb.MessageInfo
	deleted := s.state.deleted[user]
	for _, m := range s.state.messages[user] {
		if deleted != nil && deleted[m.uid] {
			continue
		}
		msgs = append(msgs, &pb.MessageInfo{
			Uid:  m.uid,
			Size: int64(len(m.data)),
		})
	}
	return &pb.ListResponse{Messages: msgs}, nil
}

func (s *testMailboxService) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	user := s.tokenUser(ctx)
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	var count int32
	var total int64
	deleted := s.state.deleted[user]
	for _, m := range s.state.messages[user] {
		if deleted != nil && deleted[m.uid] {
			continue
		}
		count++
		total += int64(len(m.data))
	}
	return &pb.StatResponse{Count: count, TotalBytes: total}, nil
}

func (s *testMailboxService) Fetch(req *pb.FetchRequest, stream grpc.ServerStreamingServer[pb.FetchResponse]) error {
	ctx := stream.Context()
	user := s.tokenUser(ctx)
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	for _, m := range s.state.messages[user] {
		if m.uid == req.Uid {
			return stream.Send(&pb.FetchResponse{Data: m.data})
		}
	}
	return status.Error(codes.NotFound, "message not found")
}

func (s *testMailboxService) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	user := s.tokenUser(ctx)
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	if s.state.deleted[user] == nil {
		s.state.deleted[user] = make(map[uint32]bool)
	}
	s.state.deleted[user][req.Uid] = true
	return &pb.DeleteResponse{}, nil
}

func (s *testMailboxService) Expunge(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	user := s.tokenUser(ctx)
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	deleted := s.state.deleted[user]
	if deleted == nil {
		return &pb.ExpungeResponse{}, nil
	}

	var remaining []*testMessage
	for _, m := range s.state.messages[user] {
		if !deleted[m.uid] {
			remaining = append(remaining, m)
		}
	}
	s.state.messages[user] = remaining
	delete(s.state.deleted, user)
	return &pb.ExpungeResponse{}, nil
}

// newTestEnv starts a full POP3S server backed by a mock session-manager gRPC server.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	smState := newTestSMState()

	// Start mock session-manager gRPC server.
	smDir := t.TempDir()
	smSocket := smDir + "/sm.sock"
	smLn, err := net.Listen("unix", smSocket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	smSrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(smSrv, &testSessionService{state: smState})
	pb.RegisterMailboxServiceServer(smSrv, &testMailboxService{state: smState})
	go func() { _ = smSrv.Serve(smLn) }()
	t.Cleanup(func() { smSrv.GracefulStop(); _ = os.RemoveAll(smDir) })

	serverTLS, clientTLS := generateTestTLS(t)

	smCfg := config.SessionManagerConfig{Socket: smSocket}

	handler := pop3.Handler("mail.test.local", mustSMClient(t, smCfg), serverTLS, &metrics.NoopCollector{})

	// Bind on a random localhost port.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	env := &testEnv{
		addr:      ln.Addr().String(),
		clientTLS: clientTLS,
		mockSM:    smState,
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

// mustSMClient creates a SessionManagerClient or fails the test.
func mustSMClient(t *testing.T, cfg config.SessionManagerConfig) *pop3.SessionManagerClient {
	t.Helper()
	client, err := pop3.NewSessionManagerClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// addUser adds a user to the mock session-manager.
func (e *testEnv) addUser(t *testing.T, username, password string) {
	t.Helper()
	e.mockSM.addUser(username+"@test.local", password)
}

// deliverMessage places a test message for the specified user.
func (e *testEnv) deliverMessage(t *testing.T, mailbox, subject, body string) {
	t.Helper()
	e.mockSM.deliverMessage(mailbox+"@test.local", subject, body)
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
	// Two users; each sees only their own messages.
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
