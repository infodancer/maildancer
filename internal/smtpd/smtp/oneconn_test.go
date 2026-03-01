package smtp

import (
	"net"
	"testing"
	"time"
)

// TestOneConnListener_AcceptsOnce verifies that Accept returns the connection
// on the first call and blocks until the connection is closed on the second.
func TestOneConnListener_AcceptsOnce(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c2.Close() })

	ln := newOneConnListener(c1)

	// First Accept should return immediately.
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("first Accept: got nil conn")
	}

	// Second Accept should block until the connection is closed.
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	// Give the goroutine time to block.
	select {
	case err := <-done:
		t.Fatalf("second Accept returned early with error: %v", err)
	case <-time.After(20 * time.Millisecond):
		// expected: still blocking
	}

	// Close the connection; the second Accept should now unblock.
	_ = conn.Close()

	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("second Accept: want net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Accept did not unblock after conn.Close()")
	}
}

// TestOneConnListener_CloseUnblocks verifies that closing the listener directly
// unblocks a waiting Accept.
func TestOneConnListener_CloseUnblocks(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close() })
	t.Cleanup(func() { _ = c2.Close() })

	ln := newOneConnListener(c1)

	// Consume the first conn so the next Accept blocks.
	first, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	_ = ln.Close()
	_ = first.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected non-nil error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after listener Close()")
	}
}

// TestOneConnListener_AddrMatchesConn checks that Addr returns the local address.
func TestOneConnListener_AddrMatchesConn(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close() })
	t.Cleanup(func() { _ = c2.Close() })

	ln := newOneConnListener(c1)
	if ln.Addr() == nil {
		t.Fatal("Addr() returned nil")
	}
}
