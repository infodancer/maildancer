package metrics

import (
	"context"
	"testing"
)

func TestNoopCollectorImplementsInterface(t *testing.T) {
	var _ Collector = &NoopCollector{}
}

func TestNoopServerImplementsInterface(t *testing.T) {
	var _ Server = &NoopServer{}
}

func TestNoopCollectorMethods(t *testing.T) {
	c := &NoopCollector{}

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
}

func TestNoopServerStart(t *testing.T) {
	s := &NoopServer{}
	ctx := context.Background()

	err := s.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v, want nil", err)
	}
}

func TestNoopServerShutdown(t *testing.T) {
	s := &NoopServer{}
	ctx := context.Background()

	err := s.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v, want nil", err)
	}
}

func TestNewDisabledMetrics(t *testing.T) {
	cfg := Config{
		Enabled: false,
		Address: ":9100",
		Path:    "/metrics",
	}

	collector, server := New(cfg)

	if collector == nil {
		t.Error("New() returned nil collector")
	}

	if server == nil {
		t.Error("New() returned nil server")
	}

	// Verify we got noop implementations
	if _, ok := collector.(*NoopCollector); !ok {
		t.Errorf("expected *NoopCollector, got %T", collector)
	}
	if _, ok := server.(*NoopServer); !ok {
		t.Errorf("expected *NoopServer, got %T", server)
	}

	// Verify the collector works
	collector.ConnectionOpened()
	collector.ConnectionClosed()

	// Verify the server works (noop returns immediately)
	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Errorf("server.Start() error = %v", err)
	}
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("server.Shutdown() error = %v", err)
	}
}
