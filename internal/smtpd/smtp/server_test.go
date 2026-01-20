package smtp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

func TestNewServer(t *testing.T) {
	backend := NewBackend(BackendConfig{
		Hostname:       "localhost",
		MaxRecipients:  100,
		MaxMessageSize: 10485760,
	})

	// Find available port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv, err := NewServer(ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Hostname:       "localhost",
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		MaxMessageSize: 10485760,
		MaxRecipients:  100,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv == nil {
		t.Fatal("expected server, got nil")
	}
	if len(srv.entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(srv.entries))
	}
}

func TestNewServerSmtpsWithoutTLS(t *testing.T) {
	backend := NewBackend(BackendConfig{
		Hostname: "localhost",
	})

	_, err := NewServer(ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: ":465", Mode: config.ModeSmtps},
		},
		Hostname: "localhost",
		// No TLS config
	})

	if err == nil {
		t.Error("expected error for SMTPS without TLS config")
	}
}

func TestServerRun(t *testing.T) {
	backend := NewBackend(BackendConfig{
		Hostname:       "localhost",
		MaxRecipients:  100,
		MaxMessageSize: 10485760,
	})

	// Find available port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv, err := NewServer(ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Hostname:       "localhost",
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		MaxMessageSize: 10485760,
		MaxRecipients:  100,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Try to connect
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}

	// Read greeting
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	greeting := string(buf[:n])
	if len(greeting) < 4 || greeting[:3] != "220" {
		t.Errorf("expected 220 greeting, got %q", greeting)
	}

	_ = conn.Close()

	// Stop the server
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServerMultipleListeners(t *testing.T) {
	backend := NewBackend(BackendConfig{
		Hostname:       "localhost",
		MaxRecipients:  100,
		MaxMessageSize: 10485760,
	})

	// Find available ports
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr1 := ln1.Addr().String()
	_ = ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr2 := ln2.Addr().String()
	_ = ln2.Close()

	srv, err := NewServer(ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: addr1, Mode: config.ModeSmtp},
			{Address: addr2, Mode: config.ModeSubmission},
		},
		Hostname:       "localhost",
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		MaxMessageSize: 10485760,
		MaxRecipients:  100,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Connect to first listener
	conn1, err := net.Dial("tcp", addr1)
	if err != nil {
		t.Fatalf("failed to connect to listener 1: %v", err)
	}
	_ = conn1.Close()

	// Connect to second listener
	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
		t.Fatalf("failed to connect to listener 2: %v", err)
	}
	_ = conn2.Close()
}
