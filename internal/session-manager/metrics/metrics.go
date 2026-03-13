// Package metrics provides interfaces and implementations for collecting
// session manager metrics. This package defines the Collector interface for
// recording metrics and the Server interface for exposing them.
package metrics

import "context"

// Collector defines the interface for recording session manager metrics.
type Collector interface {
	// Outbound queue metrics
	EnqueueCompleted(senderDomain string, status string) // status: "success", "error"
	EnqueueSize(senderDomain string, sizeBytes int64)
	DKIMSignCompleted(domain string, status string) // status: "signed", "skipped", "error"

	// Delivery proxy metrics
	DeliveryProxyCompleted(recipientDomain string, status string) // status: "success", "error"

	// Session lifecycle metrics
	SessionCreated()
	SessionClosed()
	SessionReaped()
}

// Server defines the interface for a metrics HTTP server.
type Server interface {
	// Start begins serving metrics. It blocks until the context is canceled
	// or an error occurs.
	Start(ctx context.Context) error

	// Shutdown gracefully stops the metrics server.
	Shutdown(ctx context.Context) error
}
