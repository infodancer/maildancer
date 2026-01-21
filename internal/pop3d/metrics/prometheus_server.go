package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusServer implements the Server interface and serves Prometheus metrics
// over HTTP.
type PrometheusServer struct {
	server *http.Server
}

// NewPrometheusServer creates a new PrometheusServer that will serve metrics
// at the specified address and path. Health check endpoints are registered at
// both /health and /healthz for compatibility with different conventions.
func NewPrometheusServer(address, metricsPath string) *PrometheusServer {
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	return &PrometheusServer{
		server: &http.Server{
			Addr:    address,
			Handler: mux,
		},
	}
}

// healthHandler responds with a simple JSON health status.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Start begins serving metrics. It blocks until the context is canceled
// or an error occurs. Returns nil when the server is shut down gracefully.
func (s *PrometheusServer) Start(ctx context.Context) error {
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for either context cancellation or server error
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully stops the metrics server.
func (s *PrometheusServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
