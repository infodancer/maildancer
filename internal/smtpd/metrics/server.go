package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

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
// When cfg.Enabled is true, returns Prometheus implementations.
// When cfg.Enabled is false, returns no-op implementations.
func New(cfg Config) (Collector, Server) {
	if !cfg.Enabled {
		return &NoopCollector{}, &NoopServer{}
	}

	collector := NewPrometheusCollector(prometheus.DefaultRegisterer)
	server := NewPrometheusServer(cfg.Address, cfg.Path)

	return collector, server
}
