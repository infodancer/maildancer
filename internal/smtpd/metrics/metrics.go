// Package metrics provides interfaces and implementations for collecting
// SMTP server metrics. This package defines the Collector interface for
// recording metrics and the Server interface for exposing them.
package metrics

import "context"

// Collector defines the interface for recording SMTP server metrics.
type Collector interface {
	// Connection metrics
	ConnectionOpened()
	ConnectionClosed()
	TLSConnectionEstablished()

	// Message metrics
	MessageReceived(sizeBytes int64)
	MessageRejected(reason string)

	// Authentication metrics
	AuthAttempt(success bool)

	// Command metrics
	CommandProcessed(command string)

	// Delivery metrics
	DeliveryCompleted(success bool)

	// Anti-spam metrics
	SPFCheckCompleted(result string)
	DKIMCheckCompleted(result string)
	DMARCCheckCompleted(result string)
	RBLHit(listName string)
}

// Server defines the interface for a metrics HTTP server.
type Server interface {
	// Start begins serving metrics. It blocks until the context is canceled
	// or an error occurs.
	Start(ctx context.Context) error

	// Shutdown gracefully stops the metrics server.
	Shutdown(ctx context.Context) error
}
