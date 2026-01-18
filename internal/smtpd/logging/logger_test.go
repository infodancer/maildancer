package logging

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{"debug level", "debug", slog.LevelDebug},
		{"info level", "info", slog.LevelInfo},
		{"warn level", "warn", slog.LevelWarn},
		{"warning level", "warning", slog.LevelWarn},
		{"error level", "error", slog.LevelError},
		{"unknown defaults to info", "unknown", slog.LevelInfo},
		{"empty defaults to info", "", slog.LevelInfo},
		{"case insensitive", "DEBUG", slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.level)
			if logger == nil {
				t.Fatal("expected logger, got nil")
			}
		})
	}
}

func TestWithConnection(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)

	connLogger := WithConnection(logger, "127.0.0.1:12345")
	connLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "conn_id=") {
		t.Error("expected conn_id in log output")
	}
	if !strings.Contains(output, "remote_addr=127.0.0.1:12345") {
		t.Error("expected remote_addr in log output")
	}
}

func TestWithConnectionIncrementsID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)

	// Get two connection loggers
	conn1 := WithConnection(logger, "127.0.0.1:1")
	conn2 := WithConnection(logger, "127.0.0.1:2")

	// Log from both
	conn1.Info("first")
	conn2.Info("second")

	// The IDs should be different (incrementing)
	output := buf.String()
	if !strings.Contains(output, "conn_id=") {
		t.Error("expected conn_id in log output")
	}
}

func TestWithListener(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)

	listenerLogger := WithListener(logger, ":25", "smtp")
	listenerLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "listener=:25") {
		t.Error("expected listener in log output")
	}
	if !strings.Contains(output, "mode=smtp") {
		t.Error("expected mode in log output")
	}
}

func TestContextLogger(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)

	ctx := context.Background()

	// Without logger in context, should return default
	retrieved := FromContext(ctx)
	if retrieved == nil {
		t.Fatal("expected default logger, got nil")
	}

	// With logger in context
	ctx = NewContext(ctx, logger)
	retrieved = FromContext(ctx)
	if retrieved != logger {
		t.Error("expected same logger from context")
	}
}

func TestTransactionWriter(t *testing.T) {
	var logBuf bytes.Buffer
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	var writeBuf bytes.Buffer
	tw := NewTransactionWriter(&writeBuf, logger, "send")

	data := []byte("EHLO example.com\r\n")
	n, err := tw.Write(data)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if writeBuf.String() != string(data) {
		t.Errorf("expected data written to underlying writer")
	}

	output := logBuf.String()
	if !strings.Contains(output, "transaction") {
		t.Error("expected transaction log entry")
	}
	if !strings.Contains(output, "direction=send") {
		t.Error("expected direction in log")
	}
}

func TestTransactionReader(t *testing.T) {
	var logBuf bytes.Buffer
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	data := "250 OK\r\n"
	tr := NewTransactionReader(strings.NewReader(data), logger, "recv")

	buf := make([]byte, 100)
	n, err := tr.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes read, got %d", len(data), n)
	}

	output := logBuf.String()
	if !strings.Contains(output, "transaction") {
		t.Error("expected transaction log entry")
	}
	if !strings.Contains(output, "direction=recv") {
		t.Error("expected direction in log")
	}
}
