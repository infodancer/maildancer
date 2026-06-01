package msgstore

import (
	"context"
	"io"
	"net"
	"strings"
	"time"
)

// Recipient holds the parsed components of a recipient address.
type Recipient struct {
	// Address is the canonical email without the +ext (e.g., "user@example.com").
	Address string

	// Extension is the subaddress extension, empty if none (e.g., "folder").
	Extension string
}

// ParseRecipient splits a recipient email address, separating any subaddress
// extension (plus-addressing). Examples:
//
//	"user+folder@example.com" -> Recipient{Address: "user@example.com", Extension: "folder"}
//	"user@example.com"        -> Recipient{Address: "user@example.com", Extension: ""}
//	"localuser"               -> Recipient{Address: "localuser", Extension: ""}
func ParseRecipient(email string) Recipient {
	// Split into local part and domain at the last @
	localpart := email
	domain := ""
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		localpart = email[:idx]
		domain = email[idx:] // includes the @
	}

	// Split local part on first + to extract the extension
	base, ext, _ := strings.Cut(localpart, "+")

	return Recipient{
		Address:   base + domain,
		Extension: ext,
	}
}

// DeliveryAgent handles message delivery to storage.
// smtpd calls Deliver() after a message passes filtering.
type DeliveryAgent interface {
	// Deliver stores a message for the specified recipients.
	// envelope contains sender and recipient information.
	// message is the raw RFC 5322 message content.
	Deliver(ctx context.Context, envelope Envelope, message io.Reader) error
}

// Envelope contains the message envelope information from the SMTP transaction.
type Envelope struct {
	// From is the MAIL FROM address (reverse-path).
	From string

	// Recipients contains the RCPT TO addresses (forward-paths).
	Recipients []string

	// ReceivedTime is when the message was received by the server.
	ReceivedTime time.Time

	// ClientIP is the IP address of the connecting client.
	ClientIP net.IP

	// ClientHostname is the hostname provided in EHLO/HELO.
	ClientHostname string

	// Encryption contains metadata about message encryption.
	// nil indicates plaintext (unencrypted) message.
	// Note: smtpd encrypts before delivery, msgstore only stores the blob.
	Encryption *EncryptionInfo

	// SpamResult contains the spam check result from the upstream checker.
	// nil indicates no spam check was performed (e.g., authenticated submission).
	// This is envelope metadata — the message body is never modified.
	SpamResult *SpamResult
}

// SpamResult carries the outcome of a spam check as envelope metadata.
// The delivery agent uses this to route flagged messages (e.g., to a Junk folder).
type SpamResult struct {
	// Score is the spam score from the checker (higher = more likely spam).
	Score float64

	// Action is the recommended action: "accept", "flag", "reject", "tempfail".
	Action string

	// Checker identifies which spam checker produced this result (e.g., "rspamd").
	Checker string
}
