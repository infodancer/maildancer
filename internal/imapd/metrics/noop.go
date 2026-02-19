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

// MessageFetched is a no-op.
func (n *NoopCollector) MessageFetched(userDomain string, sizeBytes int64) {}

// MessageStored is a no-op.
func (n *NoopCollector) MessageStored(userDomain string) {}

// MessageExpunged is a no-op.
func (n *NoopCollector) MessageExpunged(userDomain string) {}

// FolderSelected is a no-op.
func (n *NoopCollector) FolderSelected(userDomain string) {}
