package server

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	readData    []byte
	readPos     int
	writeData   []byte
	localAddr   net.Addr
	remoteAddr  net.Addr
	closed      bool
	deadline    time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func newMockConn() *mockConn {
	return &mockConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readPos >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) SetDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadline = t
	return nil
}

func TestNewConnection(t *testing.T) {
	mc := newMockConn()

	cfg := ConnectionConfig{
		IdleTimeout:    5 * time.Minute,
		CommandTimeout: 1 * time.Minute,
		LogTransaction: false,
		Logger:         slog.Default(),
	}

	conn := NewConnection(mc, cfg)

	if conn == nil {
		t.Fatal("expected connection, got nil")
	}
	if conn.RemoteAddr().String() != mc.remoteAddr.String() {
		t.Errorf("expected remote addr %s, got %s", mc.remoteAddr, conn.RemoteAddr())
	}
	if conn.LocalAddr().String() != mc.localAddr.String() {
		t.Errorf("expected local addr %s, got %s", mc.localAddr, conn.LocalAddr())
	}
	if conn.Logger() == nil {
		t.Error("expected logger, got nil")
	}
}

func TestConnectionReadWrite(t *testing.T) {
	mc := newMockConn()
	mc.readData = []byte("EHLO example.com\r\n")

	conn := NewConnection(mc, ConnectionConfig{})

	// Test reading
	line, err := conn.Reader().ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if line != "EHLO example.com\r\n" {
		t.Errorf("expected EHLO line, got %q", line)
	}

	// Test writing
	_, err = conn.Writer().WriteString("250 OK\r\n")
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	err = conn.Flush()
	if err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}
	if string(mc.writeData) != "250 OK\r\n" {
		t.Errorf("expected '250 OK', got %q", string(mc.writeData))
	}
}

func TestConnectionClose(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{})

	if conn.IsClosed() {
		t.Error("connection should not be closed initially")
	}

	err := conn.Close()
	if err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	if !conn.IsClosed() {
		t.Error("connection should be closed after Close()")
	}
	if !mc.closed {
		t.Error("underlying connection should be closed")
	}

	// Double close should be safe
	err = conn.Close()
	if err != nil {
		t.Fatalf("double close should not error: %v", err)
	}
}

func TestConnectionResetIdleTimeout(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{
		IdleTimeout: 5 * time.Minute,
	})

	err := conn.ResetIdleTimeout()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mc.deadline.IsZero() {
		t.Error("expected deadline to be set")
	}
}

func TestConnectionSetCommandTimeout(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{
		CommandTimeout: 1 * time.Minute,
	})

	err := conn.SetCommandTimeout()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mc.readDeadline.IsZero() {
		t.Error("expected read deadline to be set")
	}
}

func TestConnectionIdleMonitor(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{
		IdleTimeout: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go conn.IdleMonitor(ctx)

	// Wait for idle timeout to trigger
	time.Sleep(100 * time.Millisecond)

	if !conn.IsClosed() {
		t.Error("connection should be closed after idle timeout")
	}
}

func TestConnectionIdleMonitorCancellation(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{
		IdleTimeout: 5 * time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		conn.IdleMonitor(ctx)
		close(done)
	}()

	// Cancel immediately
	cancel()

	select {
	case <-done:
		// Monitor exited as expected
	case <-time.After(100 * time.Millisecond):
		t.Error("idle monitor should exit on context cancellation")
	}

	if conn.IsClosed() {
		t.Error("connection should not be closed on context cancellation")
	}
}

func TestConnectionTransactionLogging(t *testing.T) {
	mc := newMockConn()
	mc.readData = []byte("test data")

	conn := NewConnection(mc, ConnectionConfig{
		LogTransaction: true,
		Logger:         slog.Default(),
	})

	// Should have transaction wrappers
	if conn.Reader() == nil {
		t.Error("expected reader")
	}
	if conn.Writer() == nil {
		t.Error("expected writer")
	}
}

func TestConnectionUnderlying(t *testing.T) {
	mc := newMockConn()
	conn := NewConnection(mc, ConnectionConfig{})

	underlying := conn.Underlying()
	if underlying != mc {
		t.Error("expected underlying connection to be the mock")
	}
}
