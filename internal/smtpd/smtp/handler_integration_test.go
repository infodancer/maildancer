package smtp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/server"
	"github.com/infodancer/maildancer/internal/smtpd/smtp"

	smtpd "github.com/infodancer/maildancer/internal/smtpd"
)

// startTestServer starts a server with the given delivery agent and returns
// the server address and a cleanup function.
func startTestServer(t *testing.T, delivery *smtpd.MockDeliveryAgent) (string, func()) {
	t.Helper()

	// Find an available port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Hostname: "test.example.com",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	handler := smtp.Handler("test.example.com", nil, delivery, nil, nil)
	srv.SetHandler(handler)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()

	// Wait for server to be ready
	time.Sleep(50 * time.Millisecond)

	cleanup := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("warning: server did not stop in time")
		}
	}

	return addr, cleanup
}

// smtpClient is a simple SMTP client for testing.
type smtpClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialSMTP(t *testing.T, addr string) *smtpClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}

	return &smtpClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *smtpClient) close() {
	_ = c.conn.Close()
}

func (c *smtpClient) readResponse(t *testing.T) string {
	t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// readMultilineResponse reads a multi-line SMTP response and returns all lines
func (c *smtpClient) readMultilineResponse(t *testing.T) []string {
	t.Helper()

	var lines []string
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := c.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)

		// Check if this is the last line (has space after code, not dash)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return lines
}

func (c *smtpClient) sendCommand(t *testing.T, cmd string) string {
	t.Helper()

	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	if err != nil {
		t.Fatalf("failed to send command: %v", err)
	}
	return c.readResponse(t)
}

func (c *smtpClient) sendCommandMultiline(t *testing.T, cmd string) []string {
	t.Helper()

	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	if err != nil {
		t.Fatalf("failed to send command: %v", err)
	}
	return c.readMultilineResponse(t)
}

func (c *smtpClient) sendData(t *testing.T, data string) {
	t.Helper()

	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := fmt.Fprintf(c.conn, "%s\r\n.\r\n", data)
	if err != nil {
		t.Fatalf("failed to send data: %v", err)
	}
}

func TestE2ESingleRecipientDelivery(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	greeting := client.readResponse(t)
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("expected 220 greeting, got %q", greeting)
	}

	// EHLO (multi-line response)
	ehloResp := client.sendCommandMultiline(t, "EHLO client.example.com")
	if len(ehloResp) == 0 || !strings.HasPrefix(ehloResp[0], "250") {
		t.Fatalf("expected 250 response to EHLO, got %q", ehloResp)
	}

	// MAIL FROM
	resp := client.sendCommand(t, "MAIL FROM:<sender@example.com>")
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response to MAIL FROM, got %q", resp)
	}

	// RCPT TO
	resp = client.sendCommand(t, "RCPT TO:<recipient@example.com>")
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response to RCPT TO, got %q", resp)
	}

	// DATA
	resp = client.sendCommand(t, "DATA")
	if !strings.HasPrefix(resp, "354 ") {
		t.Fatalf("expected 354 response to DATA, got %q", resp)
	}

	// Send message
	message := "Subject: Test Message\r\n\r\nHello, this is a test message."
	client.sendData(t, message)

	// Read response after message
	resp = client.readResponse(t)
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response after message, got %q", resp)
	}

	// QUIT
	resp = client.sendCommand(t, "QUIT")
	if !strings.HasPrefix(resp, "221 ") {
		t.Fatalf("expected 221 response to QUIT, got %q", resp)
	}

	// Verify delivery
	if delivery.LastEnvelope == nil {
		t.Fatal("expected envelope to be captured")
	}
	if delivery.LastEnvelope.From != "sender@example.com" {
		t.Errorf("expected sender sender@example.com, got %s", delivery.LastEnvelope.From)
	}
	if len(delivery.LastEnvelope.Recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(delivery.LastEnvelope.Recipients))
	}
	if delivery.LastEnvelope.Recipients[0] != "recipient@example.com" {
		t.Errorf("expected recipient recipient@example.com, got %s", delivery.LastEnvelope.Recipients[0])
	}
	if delivery.LastEnvelope.ClientHostname != "client.example.com" {
		t.Errorf("expected client hostname client.example.com, got %s", delivery.LastEnvelope.ClientHostname)
	}
	if delivery.LastEnvelope.ClientIP == nil {
		t.Error("expected client IP to be set")
	}
	if delivery.LastEnvelope.ReceivedTime.IsZero() {
		t.Error("expected received time to be set")
	}

	// Verify message content
	if delivery.LastMessageData == nil {
		t.Fatal("expected message data to be captured")
	}
	msgStr := string(delivery.LastMessageData)
	if !strings.Contains(msgStr, "Subject: Test Message") {
		t.Errorf("expected Subject header in message, got %q", msgStr)
	}
	if !strings.Contains(msgStr, "Hello, this is a test message.") {
		t.Errorf("expected message body in message, got %q", msgStr)
	}
}

func TestE2EMultipleRecipientDelivery(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	_ = client.readResponse(t)

	// EHLO
	_ = client.sendCommandMultiline(t, "EHLO client.example.com")

	// MAIL FROM
	_ = client.sendCommand(t, "MAIL FROM:<sender@example.com>")

	// Multiple RCPT TO
	resp := client.sendCommand(t, "RCPT TO:<alice@example.com>")
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response to first RCPT TO, got %q", resp)
	}

	resp = client.sendCommand(t, "RCPT TO:<bob@example.com>")
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response to second RCPT TO, got %q", resp)
	}

	resp = client.sendCommand(t, "RCPT TO:<charlie@example.com>")
	if !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 response to third RCPT TO, got %q", resp)
	}

	// DATA
	_ = client.sendCommand(t, "DATA")

	// Send message
	message := "Subject: Multi-recipient Test\r\n\r\nThis goes to multiple recipients."
	client.sendData(t, message)
	_ = client.readResponse(t)

	// QUIT
	_ = client.sendCommand(t, "QUIT")

	// Verify delivery
	if delivery.LastEnvelope == nil {
		t.Fatal("expected envelope to be captured")
	}
	if len(delivery.LastEnvelope.Recipients) != 3 {
		t.Fatalf("expected 3 recipients, got %d", len(delivery.LastEnvelope.Recipients))
	}

	expectedRecipients := []string{"alice@example.com", "bob@example.com", "charlie@example.com"}
	for i, expected := range expectedRecipients {
		if delivery.LastEnvelope.Recipients[i] != expected {
			t.Errorf("expected recipient[%d] %s, got %s", i, expected, delivery.LastEnvelope.Recipients[i])
		}
	}
}

func TestE2EDeliveryError(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{
		ShouldError: true,
	}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	_ = client.readResponse(t)

	// Complete transaction
	_ = client.sendCommandMultiline(t, "EHLO client.example.com")
	_ = client.sendCommand(t, "MAIL FROM:<sender@example.com>")
	_ = client.sendCommand(t, "RCPT TO:<recipient@example.com>")
	_ = client.sendCommand(t, "DATA")

	// Send message
	message := "Subject: Test\r\n\r\nBody"
	client.sendData(t, message)

	// Should get error response
	resp := client.readResponse(t)
	if !strings.HasPrefix(resp, "451 ") {
		t.Fatalf("expected 451 error response, got %q", resp)
	}

	// QUIT
	_ = client.sendCommand(t, "QUIT")
}

func TestE2EDotStuffingRemoval(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	_ = client.readResponse(t)

	// Complete transaction setup
	_ = client.sendCommandMultiline(t, "EHLO client.example.com")
	_ = client.sendCommand(t, "MAIL FROM:<sender@example.com>")
	_ = client.sendCommand(t, "RCPT TO:<recipient@example.com>")
	_ = client.sendCommand(t, "DATA")

	// Send message with dot-stuffed line
	// Per RFC 5321, a line starting with "." has an extra "." prepended
	// So ".Hello" in the original becomes "..Hello" on the wire
	message := "Subject: Dot Test\r\n\r\n..Hello World"
	client.sendData(t, message)
	_ = client.readResponse(t)

	// QUIT
	_ = client.sendCommand(t, "QUIT")

	// Verify dot-stuffing was removed
	if delivery.LastMessageData == nil {
		t.Fatal("expected message data to be captured")
	}
	msgStr := string(delivery.LastMessageData)

	// The double dot should become a single dot
	if !strings.Contains(msgStr, ".Hello World") {
		t.Errorf("expected '.Hello World' (single dot) in message, got %q", msgStr)
	}
	if strings.Contains(msgStr, "..Hello") {
		t.Errorf("did not expect '..Hello' (double dot) in message, got %q", msgStr)
	}
}

func TestE2EMessageContentIntegrity(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	_ = client.readResponse(t)

	// Complete transaction setup
	_ = client.sendCommandMultiline(t, "EHLO client.example.com")
	_ = client.sendCommand(t, "MAIL FROM:<sender@example.com>")
	_ = client.sendCommand(t, "RCPT TO:<recipient@example.com>")
	_ = client.sendCommand(t, "DATA")

	// Send a message with headers and multiline body
	message := strings.Join([]string{
		"From: sender@example.com",
		"To: recipient@example.com",
		"Subject: Content Integrity Test",
		"Date: Mon, 1 Jan 2024 00:00:00 +0000",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"This is the first line of the body.",
		"This is the second line.",
		"",
		"This is after a blank line.",
	}, "\r\n")
	client.sendData(t, message)
	_ = client.readResponse(t)

	// QUIT
	_ = client.sendCommand(t, "QUIT")

	// Verify all content was preserved
	if delivery.LastMessageData == nil {
		t.Fatal("expected message data to be captured")
	}
	msgStr := string(delivery.LastMessageData)

	expectedParts := []string{
		"From: sender@example.com",
		"To: recipient@example.com",
		"Subject: Content Integrity Test",
		"MIME-Version: 1.0",
		"This is the first line of the body.",
		"This is the second line.",
		"This is after a blank line.",
	}

	for _, part := range expectedParts {
		if !strings.Contains(msgStr, part) {
			t.Errorf("expected %q in message, got %q", part, msgStr)
		}
	}
}

func TestE2EMultipleTransactions(t *testing.T) {
	delivery := &smtpd.MockDeliveryAgent{}
	addr, cleanup := startTestServer(t, delivery)
	defer cleanup()

	client := dialSMTP(t, addr)
	defer client.close()

	// Read greeting
	_ = client.readResponse(t)
	_ = client.sendCommandMultiline(t, "EHLO client.example.com")

	// First transaction
	_ = client.sendCommand(t, "MAIL FROM:<first@example.com>")
	_ = client.sendCommand(t, "RCPT TO:<recipient@example.com>")
	_ = client.sendCommand(t, "DATA")
	client.sendData(t, "Subject: First\r\n\r\nFirst message")
	_ = client.readResponse(t)

	if delivery.LastEnvelope == nil || delivery.LastEnvelope.From != "first@example.com" {
		t.Errorf("first transaction: expected sender first@example.com")
	}

	// Second transaction (reusing same connection)
	_ = client.sendCommand(t, "MAIL FROM:<second@example.com>")
	_ = client.sendCommand(t, "RCPT TO:<other@example.com>")
	_ = client.sendCommand(t, "DATA")
	client.sendData(t, "Subject: Second\r\n\r\nSecond message")
	_ = client.readResponse(t)

	if delivery.LastEnvelope == nil || delivery.LastEnvelope.From != "second@example.com" {
		t.Errorf("second transaction: expected sender second@example.com")
	}
	if delivery.LastEnvelope.Recipients[0] != "other@example.com" {
		t.Errorf("second transaction: expected recipient other@example.com")
	}
	if !strings.Contains(string(delivery.LastMessageData), "Second message") {
		t.Errorf("second transaction: expected 'Second message' in body")
	}

	// QUIT
	_ = client.sendCommand(t, "QUIT")
}
