package metrics

import "context"

// Config holds the configuration for the metrics server.
type Config struct {
	Enabled bool
	Address string
	Path    string
}

// NoopServer is a no-op implementation of the Server interface.
// It does nothing when started or shut down.
type NoopServer struct{}

// Start is a no-op that returns immediately.
func (n *NoopServer) Start(ctx context.Context) error {
	return nil
}

// Shutdown is a no-op that returns immediately.
func (n *NoopServer) Shutdown(ctx context.Context) error {
	return nil
}

// New creates a new Collector and Server based on the provided configuration.
// Currently returns no-op implementations. When Prometheus support is added,
// this function will return real implementations when cfg.Enabled is true.
func New(cfg Config) (Collector, Server) {
	return &NoopCollector{}, &NoopServer{}
}
