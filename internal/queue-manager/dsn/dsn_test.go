package dsn

import (
	"bytes"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fullBounceData() BounceData {
	return BounceData{
		Origin:     "user@example.com",
		Recipient:  "alice@gmail.com",
		Domain:     "gmail.com",
		SMTPCode:   550,
		Diagnostic: "550 5.1.1 The email account does not exist.",
		RemoteMTA:  "gmail-smtp-in.l.google.com",
		MessageID:  "abc123@example.com",
		OriginalHeaders: "From: user@example.com\r\n" +
			"To: alice@gmail.com\r\n" +
			"Subject: Hello\r\n" +
			"Message-ID: <abc123@example.com>\r\n",
		QueuedAt:  time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC),
		ExpiredAt: time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC),
		Hostname:  "mail.example.com",
	}
}

func TestGenerate_FullData(t *testing.T) {
	g, err := NewGenerator("")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := g.Generate(fullBounceData())
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parsing generated message: %v", err)
	}

	// Check top-level headers.
	if got := msg.Header.Get("From"); got != "MAILER-DAEMON@mail.example.com" {
		t.Errorf("From = %q, want MAILER-DAEMON@mail.example.com", got)
	}
	if got := msg.Header.Get("To"); got != "user@example.com" {
		t.Errorf("To = %q, want user@example.com", got)
	}
	if got := msg.Header.Get("Subject"); got != "Delivery Status Notification (Failure)" {
		t.Errorf("Subject = %q", got)
	}
	if got := msg.Header.Get("Auto-Submitted"); got != "auto-replied" {
		t.Errorf("Auto-Submitted = %q, want auto-replied", got)
	}
	if got := msg.Header.Get("MIME-Version"); got != "1.0" {
		t.Errorf("MIME-Version = %q", got)
	}
	if got := msg.Header.Get("Message-ID"); got == "" {
		t.Error("missing Message-ID")
	}

	// Parse Content-Type and verify multipart/report.
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("parsing Content-Type: %v", err)
	}
	if mediaType != "multipart/report" {
		t.Errorf("media type = %q, want multipart/report", mediaType)
	}
	if params["report-type"] != "delivery-status" {
		t.Errorf("report-type = %q, want delivery-status", params["report-type"])
	}

	// Parse MIME parts.
	reader := multipart.NewReader(msg.Body, params["boundary"])
	parts := readAllParts(t, reader)
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}

	// Part 1: text/plain with human-readable explanation.
	p1ct, _, _ := mime.ParseMediaType(parts[0].header.Get("Content-Type"))
	if p1ct != "text/plain" {
		t.Errorf("part 1 content-type = %q, want text/plain", p1ct)
	}
	body1 := parts[0].body
	if !strings.Contains(body1, "alice@gmail.com") {
		t.Error("part 1 missing recipient address")
	}
	if !strings.Contains(body1, "gmail-smtp-in.l.google.com") {
		t.Error("part 1 missing remote MTA")
	}
	if !strings.Contains(body1, "abc123@example.com") {
		t.Error("part 1 missing message ID")
	}
	if !strings.Contains(body1, "mail.example.com") {
		t.Error("part 1 missing hostname")
	}

	// Part 2: message/delivery-status.
	p2ct, _, _ := mime.ParseMediaType(parts[1].header.Get("Content-Type"))
	if p2ct != "message/delivery-status" {
		t.Errorf("part 2 content-type = %q, want message/delivery-status", p2ct)
	}
	body2 := parts[1].body
	if !strings.Contains(body2, "Reporting-MTA: dns; mail.example.com") {
		t.Error("part 2 missing Reporting-MTA")
	}
	if !strings.Contains(body2, "Final-Recipient: rfc822; alice@gmail.com") {
		t.Error("part 2 missing Final-Recipient")
	}
	if !strings.Contains(body2, "Action: failed") {
		t.Error("part 2 missing Action")
	}
	if !strings.Contains(body2, "Status: 5.1.1") {
		t.Error("part 2 missing or incorrect Status (expected 5.1.1 from diagnostic)")
	}
	if !strings.Contains(body2, "Diagnostic-Code: smtp; 550 5.1.1") {
		t.Error("part 2 missing Diagnostic-Code")
	}
	if !strings.Contains(body2, "Remote-MTA: dns; gmail-smtp-in.l.google.com") {
		t.Error("part 2 missing Remote-MTA")
	}
	if !strings.Contains(body2, "Arrival-Date:") {
		t.Error("part 2 missing Arrival-Date")
	}
	if !strings.Contains(body2, "Last-Attempt-Date:") {
		t.Error("part 2 missing Last-Attempt-Date")
	}

	// Part 3: text/rfc822-headers.
	p3ct, _, _ := mime.ParseMediaType(parts[2].header.Get("Content-Type"))
	if p3ct != "text/rfc822-headers" {
		t.Errorf("part 3 content-type = %q, want text/rfc822-headers", p3ct)
	}
	body3 := parts[2].body
	if !strings.Contains(body3, "From: user@example.com") {
		t.Error("part 3 missing original From header")
	}
	if !strings.Contains(body3, "Subject: Hello") {
		t.Error("part 3 missing original Subject header")
	}
}

func TestGenerate_MinimalData(t *testing.T) {
	g, err := NewGenerator("")
	if err != nil {
		t.Fatal(err)
	}

	data := BounceData{
		Origin:     "sender@example.com",
		Recipient:  "nobody@broken.test",
		Domain:     "broken.test",
		SMTPCode:   0,
		Diagnostic: "dial tcp 1.2.3.4:25: connection refused",
		Hostname:   "mail.example.com",
	}

	raw, err := g.Generate(data)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parsing generated message: %v", err)
	}

	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}

	reader := multipart.NewReader(msg.Body, params["boundary"])
	parts := readAllParts(t, reader)

	// With no OriginalHeaders, should only have 2 parts.
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2 (no original headers)", len(parts))
	}

	// Part 1: should not contain Remote server line.
	body1 := parts[0].body
	if strings.Contains(body1, "Remote server:") {
		t.Error("part 1 should not contain Remote server when RemoteMTA is empty")
	}
	if !strings.Contains(body1, "nobody@broken.test") {
		t.Error("part 1 missing recipient")
	}

	// Part 2: Status should be 5.0.0 (derived from smtp_code=0).
	body2 := parts[1].body
	if !strings.Contains(body2, "Status: 5.0.0") {
		t.Errorf("expected Status: 5.0.0, got: %s", body2)
	}
	if strings.Contains(body2, "Remote-MTA:") {
		t.Error("part 2 should not contain Remote-MTA when empty")
	}
	// With SMTPCode=0, Diagnostic-Code should be omitted (not an SMTP error).
	if strings.Contains(body2, "Diagnostic-Code:") {
		t.Error("part 2 should not contain Diagnostic-Code when SMTPCode is 0")
	}
}

func TestGenerate_CustomTemplate(t *testing.T) {
	tmplPath := filepath.Join(t.TempDir(), "custom.tmpl")
	if err := os.WriteFile(tmplPath, []byte("BOUNCE: {{.Recipient}} failed ({{.StatusCode}})"), 0600); err != nil {
		t.Fatal(err)
	}

	g, err := NewGenerator(tmplPath)
	if err != nil {
		t.Fatal(err)
	}

	data := fullBounceData()
	raw, err := g.Generate(data)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	reader := multipart.NewReader(msg.Body, params["boundary"])
	parts := readAllParts(t, reader)

	if !strings.Contains(parts[0].body, "BOUNCE: alice@gmail.com failed (5.1.1)") {
		t.Errorf("custom template not rendered; got: %s", parts[0].body)
	}
}

func TestNewGenerator_BadTemplatePath(t *testing.T) {
	_, err := NewGenerator("/nonexistent/template.tmpl")
	if err == nil {
		t.Error("expected error for nonexistent template path")
	}
}

func TestExtractHeaders(t *testing.T) {
	body := "From: user@example.com\nTo: alice@gmail.com\nSubject: Test\n\nBody text here.\nMore body.\n"
	path := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	headers, err := ExtractHeaders(path)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(headers, "From: user@example.com") {
		t.Error("missing From header")
	}
	if !strings.Contains(headers, "Subject: Test") {
		t.Error("missing Subject header")
	}
	if strings.Contains(headers, "Body text") {
		t.Error("body content should not be in headers")
	}
	// Should have CRLF line endings.
	if !strings.Contains(headers, "\r\n") {
		t.Error("headers should have CRLF line endings")
	}
}

func TestExtractHeaders_NoBlankLine(t *testing.T) {
	// File with no blank line (all headers, no body).
	body := "From: user@example.com\nTo: alice@gmail.com\n"
	path := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	headers, err := ExtractHeaders(path)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(headers, "From: user@example.com") {
		t.Error("missing From header")
	}
}

func TestExtractMessageID(t *testing.T) {
	cases := []struct {
		name    string
		headers string
		want    string
	}{
		{
			name:    "standard",
			headers: "From: a@b.com\r\nMessage-ID: <abc123@example.com>\r\nSubject: Hi\r\n",
			want:    "abc123@example.com",
		},
		{
			name:    "no angle brackets",
			headers: "Message-Id: bare-id@example.com\r\n",
			want:    "bare-id@example.com",
		},
		{
			name:    "missing",
			headers: "From: a@b.com\r\nSubject: Hi\r\n",
			want:    "",
		},
		{
			name:    "case insensitive",
			headers: "message-id: <CASE@test.com>\r\n",
			want:    "CASE@test.com",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractMessageID(c.headers)
			if got != c.want {
				t.Errorf("ExtractMessageID() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractEnhancedStatus(t *testing.T) {
	cases := []struct {
		diagnostic string
		smtpCode   int
		want       string
	}{
		{"550 5.1.1 The email account does not exist.", 550, "5.1.1"},
		{"452 4.2.2 Mailbox full", 452, "4.2.2"},
		{"550 No such user", 550, "5.0.0"},
		{"connection refused", 0, "5.0.0"},
		{"421 4.7.0 Try again later", 421, "4.7.0"},
		{"", 550, "5.0.0"},
		{"temporary failure", 450, "4.0.0"},
	}

	for _, c := range cases {
		got := ExtractEnhancedStatus(c.diagnostic, c.smtpCode)
		if got != c.want {
			t.Errorf("ExtractEnhancedStatus(%q, %d) = %q, want %q",
				c.diagnostic, c.smtpCode, got, c.want)
		}
	}
}

// parsedPart holds a parsed MIME part for test assertions.
type parsedPart struct {
	header textproto.MIMEHeader
	body   string
}

func readAllParts(t *testing.T, r *multipart.Reader) []parsedPart {
	t.Helper()
	var parts []parsedPart
	for {
		p, err := r.NextPart()
		if err != nil {
			break
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(p); err != nil {
			t.Fatalf("reading part: %v", err)
		}
		parts = append(parts, parsedPart{
			header: p.Header,
			body:   buf.String(),
		})
	}
	return parts
}
