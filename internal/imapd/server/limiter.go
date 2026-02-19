package server

import "sync/atomic"

// ConnectionLimiter provides thread-safe connection limit enforcement.
type ConnectionLimiter struct {
	maxConnections int64
	current        atomic.Int64
}

// NewConnectionLimiter creates a limiter with the specified maximum.
func NewConnectionLimiter(max int) *ConnectionLimiter {
	return &ConnectionLimiter{maxConnections: int64(max)}
}

// TryAcquire attempts to acquire a connection slot.
// Returns true if successful, false if at capacity.
func (l *ConnectionLimiter) TryAcquire() bool {
	for {
		current := l.current.Load()
		if current >= l.maxConnections {
			return false
		}
		if l.current.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// Release releases a connection slot.
func (l *ConnectionLimiter) Release() {
	l.current.Add(-1)
}

// Current returns the current active connection count.
func (l *ConnectionLimiter) Current() int64 {
	return l.current.Load()
}
