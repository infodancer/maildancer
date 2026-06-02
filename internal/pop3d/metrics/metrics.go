// Package metrics provides interfaces and implementations for collecting
// POP3 server metrics. This package defines the Collector interface for
// recording metrics and the Server interface for exposing them.
package metrics

import "context"

// Collector defines the interface for recording POP3 server metrics.
type Collector interface {
	// Connection metrics
	ConnectionOpened()
	ConnectionClosed()
	TLSConnectionEstablished()

	// Authentication metrics (authenticated user's domain)
	AuthAttempt(authDomain string, success bool)

	// Command metrics
	CommandProcessed(command string)

	// Message retrieval metrics
	MessageRetrieved(userDomain string, sizeBytes int64)
	MessageDeleted(userDomain string)
	MessageListed(userDomain string)
}

// Server defines the interface for a metrics HTTP server.
type Server interface {
	// Start begins serving metrics. It blocks until the context is canceled
	// or an error occurs.
	Start(ctx context.Context) error

	// Shutdown gracefully stops the metrics server.
	Shutdown(ctx context.Context) error
}
