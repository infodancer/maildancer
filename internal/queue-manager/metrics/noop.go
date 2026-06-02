package metrics

import "time"

// NoopCollector is a no-op implementation of the Collector interface.
// All methods are empty stubs that do nothing.
type NoopCollector struct{}

// DeliveryAttempted is a no-op.
func (n *NoopCollector) DeliveryAttempted(recipientDomain string) {}

// DeliveryCompleted is a no-op.
func (n *NoopCollector) DeliveryCompleted(recipientDomain string, status string) {}

// DeliveryDuration is a no-op.
func (n *NoopCollector) DeliveryDuration(recipientDomain string, duration time.Duration) {}

// BounceGenerated is a no-op.
func (n *NoopCollector) BounceGenerated(recipientDomain string, reason string) {}

// RateLimitHit is a no-op.
func (n *NoopCollector) RateLimitHit(recipientDomain string) {}

// ScanCompleted is a no-op.
func (n *NoopCollector) ScanCompleted(duration time.Duration) {}

// StaleRecovered is a no-op.
func (n *NoopCollector) StaleRecovered() {}

// QueueDepth is a no-op.
func (n *NoopCollector) QueueDepth(count int) {}
