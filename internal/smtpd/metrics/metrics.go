// Package metrics provides interfaces and implementations for collecting
// SMTP server metrics. This package defines the Collector interface for
// recording metrics and the Server interface for exposing them.
package metrics

import "context"

// Collector defines the interface for recording SMTP server metrics.
type Collector interface {
	// Connection metrics (no domain - happens before HELO)
	ConnectionOpened()
	ConnectionClosed()
	TLSConnectionEstablished()

	// Message metrics (recipient domain first)
	MessageReceived(recipientDomain string, sizeBytes int64)
	MessageRejected(recipientDomain string, reason string)

	// Authentication metrics (authenticated user's domain)
	AuthAttempt(authDomain string, success bool)

	// Command metrics (no domain - too granular)
	CommandProcessed(command string)

	// Delivery metrics (recipient domain first)
	// result should be "success", "temp_failure", or "perm_failure"
	DeliveryCompleted(recipientDomain string, result string)

	// Anti-spam metrics (sender domain first - these validate the sender)
	SPFCheckCompleted(senderDomain string, result string)
	DKIMCheckCompleted(senderDomain string, result string)
	DMARCCheckCompleted(senderDomain string, result string)
	RBLHit(listName string) // IP-based, no domain
}

// Server defines the interface for a metrics HTTP server.
type Server interface {
	// Start begins serving metrics. It blocks until the context is canceled
	// or an error occurs.
	Start(ctx context.Context) error

	// Shutdown gracefully stops the metrics server.
	Shutdown(ctx context.Context) error
}
