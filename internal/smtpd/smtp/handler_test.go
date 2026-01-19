package smtp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/server"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	readData      []byte
	readPos       int
	writeData     bytes.Buffer
	localAddr     net.Addr
	remoteAddr    net.Addr
	closed        bool
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func newMockConn() *mockConn {
	return &mockConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.writeData.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) SetDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadline = t
	return nil
}

// mockDeliveryAgent implements msgstore.DeliveryAgent for testing.
type mockDeliveryAgent struct {
	lastEnvelope    *msgstore.Envelope
	lastMessageData []byte
	shouldError     bool
	errorToReturn   error
}

func (m *mockDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if m.shouldError {
		if m.errorToReturn != nil {
			return m.errorToReturn
		}
		return io.ErrUnexpectedEOF
	}

	m.lastEnvelope = &envelope
	data, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	m.lastMessageData = data

	return nil
}

func (m *mockDeliveryAgent) Reset() {
	m.lastEnvelope = nil
	m.lastMessageData = nil
	m.shouldError = false
	m.errorToReturn = nil
}

// mockCollector records metrics calls for testing.
type mockCollector struct {
	metrics.NoopCollector
	connectionsOpened int
	connectionsClosed int
	commandsProcessed []string
	messagesReceived  int
	messagesRejected  int
}

func (m *mockCollector) ConnectionOpened() {
	m.connectionsOpened++
}

func (m *mockCollector) ConnectionClosed() {
	m.connectionsClosed++
}

func (m *mockCollector) CommandProcessed(command string) {
	m.commandsProcessed = append(m.commandsProcessed, command)
}

func (m *mockCollector) MessageReceived(recipientDomain string, sizeBytes int64) {
	m.messagesReceived++
}

func (m *mockCollector) MessageRejected(recipientDomain string, reason string) {
	m.messagesRejected++
}

func createTestConnection(input string) (*mockConn, *server.Connection) {
	mc := newMockConn()
	mc.readData = []byte(input)

	conn := server.NewConnection(mc, server.ConnectionConfig{
		IdleTimeout:    5 * time.Minute,
		CommandTimeout: 1 * time.Minute,
		Logger:         slog.Default(),
	})

	return mc, conn
}

func createTestContext() context.Context {
	ctx := context.Background()
	return logging.NewContext(ctx, slog.Default())
}

func TestHandlerGreeting(t *testing.T) {
	// Client sends QUIT immediately
	mc, conn := createTestConnection("QUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()
	if !strings.HasPrefix(output, "220 mail.example.com ESMTP ready\r\n") {
		t.Errorf("expected greeting, got %q", output)
	}
}

func TestHandlerEHLO(t *testing.T) {
	mc, conn := createTestConnection("EHLO client.example.com\r\nQUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()
	lines := strings.Split(output, "\r\n")

	// Should have greeting
	if !strings.HasPrefix(lines[0], "220 ") {
		t.Errorf("expected 220 greeting, got %q", lines[0])
	}

	// Should have EHLO response with client IP (multi-line, so 250- prefix)
	if !strings.HasPrefix(lines[1], "250-") && !strings.HasPrefix(lines[1], "250 ") {
		t.Errorf("expected 250 response to EHLO, got %q", lines[1])
	}
	if !strings.Contains(lines[1], "client.example.com") {
		t.Errorf("expected EHLO response to contain domain, got %q", lines[1])
	}
	if !strings.Contains(lines[1], "192.168.1.100") {
		t.Errorf("expected EHLO response to contain IP, got %q", lines[1])
	}
}

func TestHandlerHELO(t *testing.T) {
	mc, conn := createTestConnection("HELO client.example.com\r\nQUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()
	lines := strings.Split(output, "\r\n")

	// Should have HELO response
	if !strings.HasPrefix(lines[1], "250 ") {
		t.Errorf("expected 250 response to HELO, got %q", lines[1])
	}
}

func TestHandlerBadSequence(t *testing.T) {
	// Try MAIL FROM before EHLO
	mc, conn := createTestConnection("MAIL FROM:<sender@example.com>\r\nQUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()
	lines := strings.Split(output, "\r\n")

	// Should get 503 for bad sequence
	if !strings.HasPrefix(lines[1], "503 ") {
		t.Errorf("expected 503 for bad sequence, got %q", lines[1])
	}
}

func TestHandlerUnknownCommand(t *testing.T) {
	mc, conn := createTestConnection("EHLO test.example\r\nFOOBAR\r\nQUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Should get 500 for unknown command
	if !strings.Contains(output, "500 ") {
		t.Errorf("expected 500 for unknown command in output, got %q", output)
	}
}

func TestHandlerFullTransaction(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Subject: Test",
		"",
		"Hello World",
		".",
		"QUIT",
	}, "\r\n") + "\r\n"

	mc, conn := createTestConnection(input)
	ctx := createTestContext()

	delivery := &mockDeliveryAgent{}
	handler := Handler("mail.example.com", nil, delivery, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Check response codes
	if !strings.Contains(output, "220 ") {
		t.Error("expected 220 greeting")
	}
	if !strings.Contains(output, "354 ") {
		t.Error("expected 354 for DATA")
	}
	if !strings.Contains(output, "250 Message queued") {
		t.Errorf("expected 250 Message queued, got %q", output)
	}
	if !strings.Contains(output, "221 ") {
		t.Error("expected 221 for QUIT")
	}

	// Check delivery
	if delivery.lastEnvelope == nil {
		t.Fatal("expected envelope, got nil")
	}
	if delivery.lastEnvelope.From != "sender@example.com" {
		t.Errorf("expected sender sender@example.com, got %s", delivery.lastEnvelope.From)
	}
	if len(delivery.lastEnvelope.Recipients) != 1 || delivery.lastEnvelope.Recipients[0] != "recipient@example.com" {
		t.Errorf("expected recipient recipient@example.com, got %v", delivery.lastEnvelope.Recipients)
	}
	if delivery.lastEnvelope.ClientHostname != "client.example.com" {
		t.Errorf("expected client hostname client.example.com, got %s", delivery.lastEnvelope.ClientHostname)
	}

	// Check message data
	if delivery.lastMessageData == nil {
		t.Fatal("expected message data, got nil")
	}
	if !strings.Contains(string(delivery.lastMessageData), "Subject: Test") {
		t.Errorf("expected Subject header in message data, got %q", string(delivery.lastMessageData))
	}
	if !strings.Contains(string(delivery.lastMessageData), "Hello World") {
		t.Errorf("expected body in message data, got %q", string(delivery.lastMessageData))
	}
}

func TestHandlerDotStuffing(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Subject: Test",
		"",
		"..Hello", // Double dot should become single dot
		".",
		"QUIT",
	}, "\r\n") + "\r\n"

	mc, conn := createTestConnection(input)
	ctx := createTestContext()

	delivery := &mockDeliveryAgent{}
	handler := Handler("mail.example.com", nil, delivery, nil, nil)
	handler(ctx, conn)

	_ = mc // suppress unused warning

	// Check that dot-stuffing was handled
	if !strings.Contains(string(delivery.lastMessageData), ".Hello") {
		t.Errorf("expected .Hello (single dot) in message data, got %q", string(delivery.lastMessageData))
	}
	if strings.Contains(string(delivery.lastMessageData), "..Hello") {
		t.Errorf("did not expect ..Hello (double dot) in message data, got %q", string(delivery.lastMessageData))
	}
}

func TestHandlerRSET(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"RSET",
		"MAIL FROM:<other@example.com>",
		"QUIT",
	}, "\r\n") + "\r\n"

	mc, conn := createTestConnection(input)
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// RSET should succeed
	if strings.Count(output, "250 OK") < 3 { // EHLO, MAIL FROM, RSET should all get 250 OK
		t.Errorf("expected multiple 250 OK responses, got %q", output)
	}
}

func TestHandlerNOOP(t *testing.T) {
	mc, conn := createTestConnection("EHLO test.example\r\nNOOP\r\nNOOP with params\r\nQUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Both NOOPs should succeed
	if strings.Count(output, "250 OK") < 2 {
		t.Errorf("expected at least 2 NOOP 250 OK responses, got %q", output)
	}
}

func TestHandlerMetrics(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Subject: Test",
		"",
		"Body",
		".",
		"QUIT",
	}, "\r\n") + "\r\n"

	_, conn := createTestConnection(input)
	ctx := createTestContext()

	collector := &mockCollector{}
	delivery := &mockDeliveryAgent{}
	handler := Handler("mail.example.com", collector, delivery, nil, nil)
	handler(ctx, conn)

	if collector.connectionsOpened != 1 {
		t.Errorf("expected 1 connection opened, got %d", collector.connectionsOpened)
	}
	if collector.connectionsClosed != 1 {
		t.Errorf("expected 1 connection closed, got %d", collector.connectionsClosed)
	}
	if collector.messagesReceived != 1 {
		t.Errorf("expected 1 message received, got %d", collector.messagesReceived)
	}

	// Check commands were recorded
	expectedCommands := []string{"EHLO", "MAIL", "RCPT", "DATA", "QUIT"}
	if len(collector.commandsProcessed) != len(expectedCommands) {
		t.Errorf("expected %d commands, got %d: %v", len(expectedCommands), len(collector.commandsProcessed), collector.commandsProcessed)
	}
}

func TestHandlerNoDeliveryAgent(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Subject: Test",
		"",
		"Body",
		".",
		"QUIT",
	}, "\r\n") + "\r\n"

	mc, conn := createTestConnection(input)
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Should get 550 for no delivery agent
	if !strings.Contains(output, "550 ") {
		t.Errorf("expected 550 for no delivery agent, got %q", output)
	}
}

func TestHandlerDeliveryError(t *testing.T) {
	input := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Subject: Test",
		"",
		"Body",
		".",
		"QUIT",
	}, "\r\n") + "\r\n"

	mc, conn := createTestConnection(input)
	ctx := createTestContext()

	delivery := &mockDeliveryAgent{shouldError: true}
	collector := &mockCollector{}
	handler := Handler("mail.example.com", collector, delivery, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Should get 451 for delivery error
	if !strings.Contains(output, "451 ") {
		t.Errorf("expected 451 for delivery error, got %q", output)
	}

	// Should have recorded rejection
	if collector.messagesRejected != 1 {
		t.Errorf("expected 1 message rejected, got %d", collector.messagesRejected)
	}
}

func TestHandlerQUITResponse(t *testing.T) {
	mc, conn := createTestConnection("QUIT\r\n")
	ctx := createTestContext()

	handler := Handler("mail.example.com", nil, nil, nil, nil)
	handler(ctx, conn)

	output := mc.writeData.String()

	// Should have 221 Goodbye
	if !strings.Contains(output, "221 Goodbye") {
		t.Errorf("expected 221 Goodbye, got %q", output)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{
			name:     "tcp addr",
			addr:     &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 25},
			expected: "192.168.1.1",
		},
		{
			name:     "udp addr",
			addr:     &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53},
			expected: "10.0.0.1",
		},
		{
			name:     "nil addr",
			addr:     nil,
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractIP(tc.addr)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name       string
		recipients []string
		expected   string
	}{
		{
			name:       "single recipient",
			recipients: []string{"user@example.com"},
			expected:   "example.com",
		},
		{
			name:       "multiple recipients",
			recipients: []string{"user1@first.com", "user2@second.com"},
			expected:   "first.com",
		},
		{
			name:       "no at sign",
			recipients: []string{"localuser"},
			expected:   "unknown",
		},
		{
			name:       "empty list",
			recipients: []string{},
			expected:   "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractDomain(tc.recipients)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractCommandName(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "EHLO with domain",
			line:     "EHLO example.com",
			expected: "EHLO",
		},
		{
			name:     "lowercase mail from",
			line:     "mail from:<test@example.com>",
			expected: "MAIL",
		},
		{
			name:     "QUIT alone",
			line:     "QUIT",
			expected: "QUIT",
		},
		{
			name:     "NOOP with text",
			line:     "NOOP hello world",
			expected: "NOOP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCommandName(tc.line)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
