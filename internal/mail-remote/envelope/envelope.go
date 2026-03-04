// Package envelope parses the plain-text envelope files written by smtpd
// into the mail queue.
//
// Envelope file format (one field per line, order not required):
//
//	TTL 2026-03-07T10:00:00Z
//	SENDER bounces+alice=gmail.com@origin.example.com
//	RECIPIENT alice@gmail.com
//	MSGID abc123def456789
package envelope

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Envelope holds the parsed contents of a single queue envelope file.
type Envelope struct {
	// Path is the filesystem path to this envelope file.
	Path string

	// TTL is the absolute expiry time. After this time, one last delivery
	// attempt is made via SMTP and the envelope is removed regardless.
	TTL time.Time

	// Sender is the VERP-encoded MAIL FROM address for this recipient.
	Sender string

	// Recipient is the RCPT TO address.
	Recipient string

	// MsgID is the message body identifier, used to locate the body file.
	MsgID string
}

// RecipientDomain returns the domain part of the Recipient address.
func (e *Envelope) RecipientDomain() (string, error) {
	_, domain, ok := strings.Cut(e.Recipient, "@")
	if !ok {
		return "", fmt.Errorf("envelope %s: recipient %q has no domain", e.Path, e.Recipient)
	}
	return domain, nil
}

// Expired reports whether the envelope TTL has passed.
func (e *Envelope) Expired() bool {
	return time.Now().After(e.TTL)
}

// Parse reads and parses an envelope file from path.
func Parse(path string) (*Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open envelope %s: %w", path, err)
	}
	defer f.Close()

	env := &Envelope{Path: path}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("envelope %s: malformed line %q", path, line)
		}
		value = strings.TrimSpace(value)
		switch strings.ToUpper(key) {
		case "TTL":
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, fmt.Errorf("envelope %s: invalid TTL %q: %w", path, value, err)
			}
			env.TTL = t
		case "SENDER":
			env.Sender = value
		case "RECIPIENT":
			env.Recipient = value
		case "MSGID":
			env.MsgID = value
		default:
			// Unknown fields are silently ignored for forward compatibility.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading envelope %s: %w", path, err)
	}

	if err := env.validate(); err != nil {
		return nil, err
	}
	return env, nil
}

func (e *Envelope) validate() error {
	if e.TTL.IsZero() {
		return fmt.Errorf("envelope %s: missing TTL", e.Path)
	}
	if e.Sender == "" {
		return fmt.Errorf("envelope %s: missing SENDER", e.Path)
	}
	if e.Recipient == "" {
		return fmt.Errorf("envelope %s: missing RECIPIENT", e.Path)
	}
	if e.MsgID == "" {
		return fmt.Errorf("envelope %s: missing MSGID", e.Path)
	}
	return nil
}
