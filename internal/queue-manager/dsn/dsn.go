// Package dsn generates RFC 3464 Delivery Status Notifications (bounce messages).
package dsn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/bounce.text.tmpl
var defaultTemplateText string

// BounceData contains all information needed to generate a DSN bounce message.
type BounceData struct {
	// Who to notify (original authenticated submitter).
	Origin string

	// Failed delivery details.
	Recipient  string // Recipient whose delivery failed
	Domain     string // Recipient domain
	SMTPCode   int    // Three-digit SMTP reply code; 0 if no SMTP response
	Diagnostic string // SMTP reply text or error string
	RemoteMTA  string // MX hostname that rejected (may be empty)

	// Original message info.
	MessageID       string // Original Message-ID header value
	OriginalHeaders string // Original message headers (up to first blank line)

	// Timing.
	QueuedAt  time.Time // When the message entered the queue (envelope "created" field)
	ExpiredAt time.Time // When TTL expired (zero for mid-queue failures)

	// System.
	Hostname string // Reporting MTA hostname
}

// templateData is passed to the text/template for the human-readable part.
type templateData struct {
	Recipient  string
	Domain     string
	StatusCode string
	SMTPCode   int
	Diagnostic string
	RemoteMTA  string
	MessageID  string
	QueuedAt   string
	ExpiredAt  string
	Hostname   string
}

// Generator builds DSN bounce messages.
type Generator struct {
	tmpl *template.Template
}

// NewGenerator creates a DSN generator. If customTemplatePath is empty,
// the embedded default template is used.
func NewGenerator(customTemplatePath string) (*Generator, error) {
	var tmpl *template.Template
	var err error

	if customTemplatePath != "" {
		data, readErr := os.ReadFile(customTemplatePath)
		if readErr != nil {
			return nil, fmt.Errorf("reading bounce template: %w", readErr)
		}
		tmpl, err = template.New("bounce").Parse(string(data))
	} else {
		tmpl, err = template.New("bounce").Parse(defaultTemplateText)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing bounce template: %w", err)
	}

	return &Generator{tmpl: tmpl}, nil
}

// Generate produces a complete RFC 3464 DSN bounce message. The returned
// bytes contain a full RFC 822 message with a multipart/report body.
func (g *Generator) Generate(data BounceData) ([]byte, error) {
	var buf bytes.Buffer

	boundary := generateBoundary()
	dsnMsgID := generateMessageID(data.Hostname)
	statusCode := ExtractEnhancedStatus(data.Diagnostic, data.SMTPCode)

	// Top-level message headers.
	writeHeader(&buf, "From", fmt.Sprintf("MAILER-DAEMON@%s", data.Hostname))
	writeHeader(&buf, "To", data.Origin)
	writeHeader(&buf, "Date", time.Now().UTC().Format(time.RFC1123Z))
	writeHeader(&buf, "Subject", "Delivery Status Notification (Failure)")
	writeHeader(&buf, "Message-ID", fmt.Sprintf("<%s>", dsnMsgID))
	writeHeader(&buf, "MIME-Version", "1.0")
	writeHeader(&buf, "Content-Type",
		fmt.Sprintf("multipart/report; report-type=delivery-status; boundary=%q", boundary))
	writeHeader(&buf, "Auto-Submitted", "auto-replied")
	buf.WriteString("\r\n")

	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, fmt.Errorf("setting MIME boundary: %w", err)
	}

	if err := g.writePart1(w, data, statusCode); err != nil {
		return nil, fmt.Errorf("writing human-readable part: %w", err)
	}

	if err := writePart2(w, data, statusCode); err != nil {
		return nil, fmt.Errorf("writing delivery-status part: %w", err)
	}

	if data.OriginalHeaders != "" {
		if err := writePart3(w, data.OriginalHeaders); err != nil {
			return nil, fmt.Errorf("writing original headers part: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing multipart writer: %w", err)
	}

	return buf.Bytes(), nil
}

// writePart1 renders the human-readable explanation from the template.
func (g *Generator) writePart1(w *multipart.Writer, data BounceData, statusCode string) error {
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	part, err := w.CreatePart(hdr)
	if err != nil {
		return err
	}

	td := templateData{
		Recipient:  data.Recipient,
		Domain:     data.Domain,
		StatusCode: statusCode,
		SMTPCode:   data.SMTPCode,
		Diagnostic: data.Diagnostic,
		RemoteMTA:  data.RemoteMTA,
		MessageID:  data.MessageID,
		Hostname:   data.Hostname,
	}

	if !data.QueuedAt.IsZero() {
		td.QueuedAt = data.QueuedAt.UTC().Format(time.RFC1123Z)
	}
	if !data.ExpiredAt.IsZero() {
		td.ExpiredAt = data.ExpiredAt.UTC().Format(time.RFC1123Z)
	}

	return g.tmpl.Execute(part, td)
}

// writePart2 writes the message/delivery-status part with per-message and
// per-recipient fields as defined by RFC 3464.
func writePart2(w *multipart.Writer, data BounceData, statusCode string) error {
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Type", "message/delivery-status")
	part, err := w.CreatePart(hdr)
	if err != nil {
		return err
	}

	var b bytes.Buffer

	// Per-message fields.
	fmt.Fprintf(&b, "Reporting-MTA: dns; %s\r\n", data.Hostname)
	if !data.QueuedAt.IsZero() {
		fmt.Fprintf(&b, "Arrival-Date: %s\r\n", data.QueuedAt.UTC().Format(time.RFC1123Z))
	}

	// Blank line between per-message and per-recipient fields.
	b.WriteString("\r\n")

	// Per-recipient fields.
	fmt.Fprintf(&b, "Final-Recipient: rfc822; %s\r\n", data.Recipient)
	b.WriteString("Action: failed\r\n")
	fmt.Fprintf(&b, "Status: %s\r\n", statusCode)
	if data.Diagnostic != "" && data.SMTPCode > 0 {
		fmt.Fprintf(&b, "Diagnostic-Code: smtp; %s\r\n", data.Diagnostic)
	}
	if data.RemoteMTA != "" {
		fmt.Fprintf(&b, "Remote-MTA: dns; %s\r\n", data.RemoteMTA)
	}
	fmt.Fprintf(&b, "Last-Attempt-Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))

	_, err = part.Write(b.Bytes())
	return err
}

// writePart3 writes the text/rfc822-headers part containing the original
// message headers.
func writePart3(w *multipart.Writer, headers string) error {
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Type", "text/rfc822-headers")
	part, err := w.CreatePart(hdr)
	if err != nil {
		return err
	}

	// Normalize line endings to CRLF.
	normalized := strings.ReplaceAll(headers, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\n", "\r\n")
	_, err = io.WriteString(part, normalized)
	return err
}

// ExtractHeaders reads the headers from a message body file, up to the first
// blank line. Returns the raw header text with CRLF line endings.
func ExtractHeaders(bodyPath string) (result string, err error) {
	f, err := os.Open(bodyPath)
	if err != nil {
		return "", err
	}
	defer func() {
		if cErr := f.Close(); cErr != nil && err == nil {
			err = cErr
		}
	}()

	var headers strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		headers.WriteString(line)
		headers.WriteString("\r\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return headers.String(), nil
}

// ExtractMessageID extracts the Message-ID value from raw headers.
// Returns the bare ID without angle brackets, or empty string if not found.
func ExtractMessageID(headers string) string {
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), "message-id:") {
			val := strings.TrimSpace(line[len("message-id:"):])
			return strings.Trim(val, "<>")
		}
	}
	return ""
}

func writeHeader(w *bytes.Buffer, key, value string) {
	fmt.Fprintf(w, "%s: %s\r\n", key, value)
}

// enhancedStatusRe matches RFC 3463 enhanced status codes (e.g., "5.1.1")
// while avoiding false positives from IP addresses. The negative character
// class [^.\d] before the code prevents matching within dotted sequences
// like "1.2.3.4".
var enhancedStatusRe = regexp.MustCompile(`(?:^|[^.\d])([245]\.\d+\.\d+)\b`)

// ExtractEnhancedStatus tries to find an RFC 3463 enhanced status code
// (e.g., "5.1.1") in the diagnostic string. If not found, derives a generic
// one from the SMTP reply code.
func ExtractEnhancedStatus(diagnostic string, smtpCode int) string {
	if m := enhancedStatusRe.FindStringSubmatch(diagnostic); len(m) > 1 {
		return m[1]
	}
	if smtpCode >= 400 && smtpCode < 500 {
		return "4.0.0"
	}
	return "5.0.0"
}

func generateBoundary() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("dsn_%d", time.Now().UnixNano())
	}
	return "dsn_" + hex.EncodeToString(b)
}

func generateMessageID(hostname string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("dsn-%d@%s", time.Now().UnixNano(), hostname)
	}
	return fmt.Sprintf("dsn-%s@%s", hex.EncodeToString(b), hostname)
}
