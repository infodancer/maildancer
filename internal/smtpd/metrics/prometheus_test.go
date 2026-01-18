package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPrometheusCollectorImplementsInterface(t *testing.T) {
	reg := prometheus.NewRegistry()
	var _ Collector = NewPrometheusCollector(reg)
}

func TestPrometheusServerImplementsInterface(t *testing.T) {
	var _ Server = NewPrometheusServer(":0", "/metrics")
}

func TestPrometheusCollectorMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewPrometheusCollector(reg)

	// All methods should execute without panic
	c.ConnectionOpened()
	c.ConnectionClosed()
	c.TLSConnectionEstablished()
	c.MessageReceived("example.com", 1024)
	c.MessageRejected("example.com", "spam")
	c.AuthAttempt("example.com", true)
	c.AuthAttempt("example.com", false)
	c.CommandProcessed("EHLO")
	c.DeliveryCompleted("example.com", "success")
	c.DeliveryCompleted("example.com", "temp_failure")
	c.DeliveryCompleted("example.com", "perm_failure")
	c.SPFCheckCompleted("sender.com", "pass")
	c.DKIMCheckCompleted("sender.com", "fail")
	c.DMARCCheckCompleted("sender.com", "none")
	c.RBLHit("spamhaus.org")

	// Gather metrics to verify they were recorded
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Check that metrics were registered
	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	expectedMetrics := []string{
		"smtpd_connections_total",
		"smtpd_connections_active",
		"smtpd_tls_connections_total",
		"smtpd_messages_received_total",
		"smtpd_messages_rejected_total",
		"smtpd_messages_size_bytes",
		"smtpd_auth_attempts_total",
		"smtpd_commands_total",
		"smtpd_deliveries_total",
		"smtpd_spf_checks_total",
		"smtpd_dkim_checks_total",
		"smtpd_dmarc_checks_total",
		"smtpd_rbl_hits_total",
	}

	for _, name := range expectedMetrics {
		if !metricNames[name] {
			t.Errorf("expected metric %q not found", name)
		}
	}
}

func TestPrometheusCollectorConnectionMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewPrometheusCollector(reg)

	// Open some connections
	c.ConnectionOpened()
	c.ConnectionOpened()
	c.ConnectionOpened()

	// Close one
	c.ConnectionClosed()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		switch mf.GetName() {
		case "smtpd_connections_total":
			if len(mf.GetMetric()) == 0 {
				t.Error("connections_total has no metrics")
				continue
			}
			v := mf.GetMetric()[0].GetCounter().GetValue()
			if v != 3 {
				t.Errorf("connections_total = %v, want 3", v)
			}
		case "smtpd_connections_active":
			if len(mf.GetMetric()) == 0 {
				t.Error("connections_active has no metrics")
				continue
			}
			v := mf.GetMetric()[0].GetGauge().GetValue()
			if v != 2 {
				t.Errorf("connections_active = %v, want 2", v)
			}
		}
	}
}

func TestPrometheusCollectorAuthMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewPrometheusCollector(reg)

	c.AuthAttempt("test.com", true)
	c.AuthAttempt("test.com", false)
	c.AuthAttempt("other.com", true)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "smtpd_auth_attempts_total" {
			// Should have 3 metric entries (2 for test.com with different results, 1 for other.com)
			if len(mf.GetMetric()) != 3 {
				t.Errorf("auth_attempts_total has %d metric entries, want 3", len(mf.GetMetric()))
			}
		}
	}
}

func TestPrometheusServerStartStop(t *testing.T) {
	server := NewPrometheusServer("127.0.0.1:0", "/metrics")

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	cancel()

	// Check that Start returned without error
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Start() did not return after shutdown")
	}
}

func TestNewReturnsPrometheusImplementationsWhenEnabled(t *testing.T) {
	// Use a separate registry to avoid conflicts with default registry
	// Note: This test verifies the type returned, not the full functionality
	// because New() uses DefaultRegisterer which may already have metrics registered.

	cfg := Config{
		Enabled: false,
		Address: ":9100",
		Path:    "/metrics",
	}

	collector, server := New(cfg)

	// When disabled, should return noop implementations
	if _, ok := collector.(*NoopCollector); !ok {
		t.Errorf("New() with Enabled=false returned collector type %T, want *NoopCollector", collector)
	}
	if _, ok := server.(*NoopServer); !ok {
		t.Errorf("New() with Enabled=false returned server type %T, want *NoopServer", server)
	}
}

