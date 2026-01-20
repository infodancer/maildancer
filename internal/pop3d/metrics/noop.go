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

// AuthAttempt is a no-op.
func (n *NoopCollector) AuthAttempt(authDomain string, success bool) {}

// CommandProcessed is a no-op.
func (n *NoopCollector) CommandProcessed(command string) {}

// MessageRetrieved is a no-op.
func (n *NoopCollector) MessageRetrieved(userDomain string, sizeBytes int64) {}

// MessageDeleted is a no-op.
func (n *NoopCollector) MessageDeleted(userDomain string) {}

// MessageListed is a no-op.
func (n *NoopCollector) MessageListed(userDomain string) {}
