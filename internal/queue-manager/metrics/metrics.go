// Package metrics provides interfaces and implementations for collecting
// queue-manager metrics. This package defines the Collector interface for
// recording metrics and the Server interface for exposing them.
package metrics

import (
	"context"
	"time"
)

// Collector defines the interface for recording queue-manager metrics.
type Collector interface {
	DeliveryAttempted(recipientDomain string)
	DeliveryCompleted(recipientDomain string, status string) // status: "delivered", "perm_fail", "temp_fail"
	DeliveryDuration(recipientDomain string, duration time.Duration)
	BounceGenerated(recipientDomain string, reason string) // reason: "expired", "permanent"
	RateLimitHit(recipientDomain string)
	ScanCompleted(duration time.Duration)
	StaleRecovered()
	QueueDepth(count int) // gauge: set on each scan
}

// Server defines the interface for a metrics HTTP server.
type Server interface {
	// Start begins serving metrics. It blocks until the context is canceled
	// or an error occurs.
	Start(ctx context.Context) error

	// Shutdown gracefully stops the metrics server.
	Shutdown(ctx context.Context) error
}
