// Package protocol defines the wire protocol between a mail dispatcher (e.g. smtpd)
// and the mail-deliver delivery agent. This package is authoritative — any process
// that spawns mail-deliver must import it for the request and response types.
//
// Wire format:
//
//	stdin:  JSON-encoded DeliverRequest terminated by '\n', followed by raw RFC 5322
//	        message bytes until EOF.
//	stdout: JSON-encoded DeliverResponse terminated by '\n', written before exit.
//
// The dispatcher sets uid/gid on the child process via SysProcAttr.Credential
// before exec — mail-deliver never calls setuid/setgid itself.
package protocol

// Version is the current wire protocol version.
const Version = 1

// DeliverRequest is the JSON envelope sent by the dispatcher on stdin line 1.
// Raw message bytes follow on stdin until EOF.
type DeliverRequest struct {
	// Version must equal protocol.Version; requests with unknown versions are rejected.
	Version int `json:"version"`

	// Sender is the MAIL FROM reverse-path (may be empty string for bounces).
	Sender string `json:"sender"`

	// Recipients contains the RCPT TO forward-paths. smtpd enforces one recipient
	// per message; the slice is kept for generality.
	Recipients []string `json:"recipients"`

	// ReceivedTime is when the message was accepted by the upstream daemon (RFC3339).
	ReceivedTime string `json:"received_time,omitempty"`

	// ClientIP is the IP address of the SMTP client that submitted the message.
	ClientIP string `json:"client_ip,omitempty"`

	// ClientHostname is the hostname from EHLO/HELO.
	ClientHostname string `json:"client_hostname,omitempty"`

	// Forwarded indicates this delivery is the result of a forwarding rule expansion.
	// When true, mail-deliver skips forwarding resolution to enforce the 1-hop limit.
	Forwarded bool `json:"forwarded,omitempty"`
}

// DeliverResponse is the JSON result written to stdout by mail-deliver before exit.
type DeliverResponse struct {
	// Version is always protocol.Version.
	Version int `json:"version"`

	// Result is one of the Result* constants below.
	Result string `json:"result"`

	// Addresses contains redirect target addresses when Result == ResultRedirected.
	// Multiple addresses are valid (e.g. a forwarding rule with comma-separated targets).
	Addresses []string `json:"addresses,omitempty"`

	// Temporary qualifies a ResultRejected response: true means the dispatcher
	// should return a 4xx temporary failure; false means a 5xx permanent failure.
	Temporary bool `json:"temporary,omitempty"`

	// Reason is a human-readable explanation for ResultRejected responses.
	// Not sent to the remote SMTP client; used for logging only.
	Reason string `json:"reason,omitempty"`
}

// Result values for DeliverResponse.Result.
const (
	// ResultDelivered means the message was successfully written to the maildir.
	ResultDelivered = "delivered"

	// ResultRejected means delivery was refused. Check Temporary and Reason.
	ResultRejected = "rejected"

	// ResultRedirected means the message should be delivered to Addresses instead.
	// The dispatcher re-delivers once with Forwarded=true (1-hop limit).
	ResultRedirected = "redirected"
)
