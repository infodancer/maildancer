package smtp

import (
	"net"
	"sync"
)

// oneConnListener is a net.Listener that serves exactly one connection.
// After the single connection is accepted and subsequently closed, Accept returns
// net.ErrClosed. Used by protocol-handler subprocesses to run one SMTP session.
//
// Two separate channels provide safe concurrent signalling:
//   - connDone: closed exclusively by notifyConn.Close() when the session ends
//   - stopped:  closed exclusively by oneConnListener.Close()
//
// This separation avoids the double-close race that would occur if both paths
// tried to close the same channel.
type oneConnListener struct {
	mu       sync.Mutex
	conn     net.Conn    // nil after first Accept
	connDone chan struct{} // session-end signal (owned by notifyConn)
	stopped  chan struct{} // listener-close signal (owned by this listener)
	stopOnce sync.Once
	addr     net.Addr
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	return &oneConnListener{
		conn:     conn,
		connDone: make(chan struct{}),
		stopped:  make(chan struct{}),
		addr:     conn.LocalAddr(),
	}
}

// Accept returns the wrapped connection on the first call.
// On subsequent calls it blocks until the connection closes or the listener is
// closed, then returns net.ErrClosed.
func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()

	if c != nil {
		return &notifyConn{Conn: c, done: l.connDone}, nil
	}

	select {
	case <-l.connDone:
		return nil, net.ErrClosed
	case <-l.stopped:
		return nil, net.ErrClosed
	}
}

// Close signals any blocked Accept to unblock. Safe to call multiple times.
func (l *oneConnListener) Close() error {
	l.stopOnce.Do(func() { close(l.stopped) })
	return nil
}

// Addr returns the local address of the underlying connection.
func (l *oneConnListener) Addr() net.Addr { return l.addr }

// notifyConn wraps a net.Conn and closes the connDone channel when Close is
// called, signalling oneConnListener that the session has ended.
// The done channel is exclusively owned by notifyConn; only closeOnce.Do
// ever closes it.
type notifyConn struct {
	net.Conn
	closeOnce sync.Once
	done      chan struct{}
}

func (c *notifyConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.Conn.Close()
}
