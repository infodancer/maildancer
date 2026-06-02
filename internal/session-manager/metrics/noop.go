package metrics

// NoopCollector is a no-op implementation of the Collector interface.
// All methods are empty stubs that do nothing.
type NoopCollector struct{}

// EnqueueCompleted is a no-op.
func (n *NoopCollector) EnqueueCompleted(senderDomain string, status string) {}

// EnqueueSize is a no-op.
func (n *NoopCollector) EnqueueSize(senderDomain string, sizeBytes int64) {}

// DKIMSignCompleted is a no-op.
func (n *NoopCollector) DKIMSignCompleted(domain string, status string) {}

// DeliveryProxyCompleted is a no-op.
func (n *NoopCollector) DeliveryProxyCompleted(recipientDomain string, status string) {}

// SessionCreated is a no-op.
func (n *NoopCollector) SessionCreated() {}

// SessionClosed is a no-op.
func (n *NoopCollector) SessionClosed() {}

// SessionReaped is a no-op.
func (n *NoopCollector) SessionReaped() {}
