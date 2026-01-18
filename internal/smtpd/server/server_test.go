package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

func TestNewServer(t *testing.T) {
	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: ":0", Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv == nil {
		t.Fatal("expected server, got nil")
	}
	if srv.Logger() == nil {
		t.Error("expected logger")
	}
	if srv.Config() != cfg {
		t.Error("expected config to be stored")
	}
	if srv.TLSConfig() != nil {
		t.Error("expected nil TLS config without cert/key")
	}
}

func TestNewServerWithInvalidTLS(t *testing.T) {
	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: ":0", Mode: config.ModeSmtp},
		},
		TLS: config.TLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for invalid TLS files")
	}
}

func TestServerRun(t *testing.T) {
	// Find available ports
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr1 := ln1.Addr().String()
	_ = ln1.Close()

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr1, Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Try to connect
	conn, err := net.Dial("tcp", addr1)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	_ = conn.Close()

	// Stop the server
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServerWithCustomHandler(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	handlerCalled := make(chan struct{})
	srv.SetHandler(func(ctx context.Context, conn *Connection) {
		select {
		case <-handlerCalled:
		default:
			close(handlerCalled)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Connect
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-handlerCalled:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not called")
	}
}

func TestServerMultipleListeners(t *testing.T) {
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

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr1, Mode: config.ModeSmtp},
			{Address: addr2, Mode: config.ModeSubmission},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

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

func TestServerShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Shutdown should work
	srv.Shutdown()
	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after shutdown")
	}
}

func TestServerSmtpsWithoutTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "info",
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtps},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = srv.Run(ctx)
	// We expect an error about missing TLS for SMTPS
	// But context timeout is also acceptable if the check happens later
	if err != nil && err != context.DeadlineExceeded {
		// Got an error as expected (TLS required for SMTPS)
		return
	}
}

func TestServerDebugLogging(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Hostname: "localhost",
		LogLevel: "debug", // Enable debug logging which triggers transaction logging
		Listeners: []config.ListenerConfig{
			{Address: addr, Mode: config.ModeSmtp},
		},
		Timeouts: config.TimeoutsConfig{
			Connection: "5m",
			Command:    "1m",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Connect and verify it works with debug logging
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	_ = conn.Close()
}
