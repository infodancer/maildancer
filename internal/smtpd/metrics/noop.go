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
func (n *NoopCollector) MessageReceived(sizeBytes int64) {}

// MessageRejected is a no-op.
func (n *NoopCollector) MessageRejected(reason string) {}

// AuthAttempt is a no-op.
func (n *NoopCollector) AuthAttempt(success bool) {}

// CommandProcessed is a no-op.
func (n *NoopCollector) CommandProcessed(command string) {}

// DeliveryCompleted is a no-op.
func (n *NoopCollector) DeliveryCompleted(success bool) {}

// SPFCheckCompleted is a no-op.
func (n *NoopCollector) SPFCheckCompleted(result string) {}

// DKIMCheckCompleted is a no-op.
func (n *NoopCollector) DKIMCheckCompleted(result string) {}

// DMARCCheckCompleted is a no-op.
func (n *NoopCollector) DMARCCheckCompleted(result string) {}

// RBLHit is a no-op.
func (n *NoopCollector) RBLHit(listName string) {}
