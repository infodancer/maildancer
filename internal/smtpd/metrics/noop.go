package metrics

// NoopCollector is a no-op implementation of the Collector interface.
// All methods are empty stubs that do nothing.
type NoopCollector struct{}

// ConnectionOpened is a no-op.
func (n *NoopCollector) ConnectionOpened() {}

// ConnectionClosed is a no-op.
func (n *NoopCollector) ConnectionClosed() {}

// TLSConnectionEstablished is a no-op.
func (n *NoopCollector) TLSConnectionEstablished() {}

// MessageReceived is a no-op.
func (n *NoopCollector) MessageReceived(recipientDomain string, sizeBytes int64) {}

// MessageRejected is a no-op.
func (n *NoopCollector) MessageRejected(recipientDomain string, reason string) {}

// AuthAttempt is a no-op.
func (n *NoopCollector) AuthAttempt(authDomain string, success bool) {}

// CommandProcessed is a no-op.
func (n *NoopCollector) CommandProcessed(command string) {}

// DeliveryCompleted is a no-op.
func (n *NoopCollector) DeliveryCompleted(recipientDomain string, result string) {}

// SPFCheckCompleted is a no-op.
func (n *NoopCollector) SPFCheckCompleted(senderDomain string, result string) {}

// DKIMCheckCompleted is a no-op.
func (n *NoopCollector) DKIMCheckCompleted(senderDomain string, result string) {}

// DMARCCheckCompleted is a no-op.
func (n *NoopCollector) DMARCCheckCompleted(senderDomain string, result string) {}

// RBLHit is a no-op.
func (n *NoopCollector) RBLHit(listName string) {}
