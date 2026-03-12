// Package envelope parses the JSON envelope files written by smtpd
// into the mail queue.
//
// Envelope file format (JSON):
//
//	{
//	  "ttl": "2026-03-07T10:00:00Z",
//	  "created": "2026-02-28T10:00:00Z",
//	  "sender": "bounces+alice=gmail.com@origin.example.com",
//	  "recipient": "alice@gmail.com",
//	  "msgid": "abc123def456789@example.com",
//	  "origin": "user@example.com"
//	}
package envelope

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Envelope holds the parsed contents of a single queue envelope file.
type Envelope struct {
	// Path is the filesystem path to this envelope file.
	Path string `json:"-"`

	// TTL is the absolute expiry time. After this time, one last delivery
	// attempt is made via SMTP and the envelope is removed regardless.
	TTL time.Time `json:"ttl"`

	// Created is the queue-inject timestamp.
	Created time.Time `json:"created"`

	// Sender is the VERP-encoded MAIL FROM address for this recipient.
	Sender string `json:"sender"`

	// Recipient is the RCPT TO address.
	Recipient string `json:"recipient"`

	// MsgID is the message body identifier, used to locate the body file.
	MsgID string `json:"msgid"`

	// Origin is the authenticated submitter's address before VERP rewriting.
	Origin string `json:"origin"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open envelope %s: %w", path, err)
	}

	env := &Envelope{Path: path}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("envelope %s: %w", path, err)
	}

	if err := env.validate(); err != nil {
		return nil, err
	}
	return env, nil
}

func (e *Envelope) validate() error {
	if e.TTL.IsZero() {
		return fmt.Errorf("envelope %s: missing ttl", e.Path)
	}
	if e.Sender == "" {
		return fmt.Errorf("envelope %s: missing sender", e.Path)
	}
	if e.Recipient == "" {
		return fmt.Errorf("envelope %s: missing recipient", e.Path)
	}
	if e.MsgID == "" {
		return fmt.Errorf("envelope %s: missing msgid", e.Path)
	}
	return nil
}
