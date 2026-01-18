package msgstore

import (
	"context"
	"io"
	"net"
	"time"
)

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
}
