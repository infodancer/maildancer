package connfork

import (
	"net"
	"sync"
)

// oneConnListener is a net.Listener that serves exactly one connection.
// After the single connection is accepted and subsequently closed, Accept
// returns net.ErrClosed. Handler subprocesses use it to run one session
// through a protocol library that only exposes Serve(net.Listener).
//
// Two separate channels provide safe concurrent signalling:
//   - connDone: closed exclusively by notifyConn.Close() when the session ends
//   - stopped:  closed exclusively by oneConnListener.Close()
//
// This separation avoids the double-close race that would occur if both paths
// tried to close the same channel.
type oneConnListener struct {
	mu       sync.Mutex
	conn     net.Conn      // nil after first Accept
	connDone chan struct{} // session-end signal (owned by notifyConn)
	stopped  chan struct{} // listener-close signal (owned by this listener)
	stopOnce sync.Once
	addr     net.Addr
	wrap     func(net.Conn) net.Conn // applied outside the notify shim; nil = none
}

// NewOneConnListener wraps an already-accepted connection in a net.Listener
// that yields it exactly once.
func NewOneConnListener(conn net.Conn) net.Listener {
	return NewOneConnListenerWrapped(conn, nil)
}

// NewOneConnListenerWrapped is NewOneConnListener with a layer applied
// OUTSIDE the session-end notify shim: Accept yields wrap(shim(conn)).
// Protocol libraries that type-assert the accepted connection to a concrete
// type -- go-imap checks for *tls.Conn to decide whether the session is
// secure -- need that layer outermost; wrapping TLS around conn before
// NewOneConnListener would hide it behind the shim (issue #199). The close
// chain is preserved: closing the outer layer closes the shim, which signals
// session end.
func NewOneConnListenerWrapped(conn net.Conn, wrap func(net.Conn) net.Conn) net.Listener {
	return &oneConnListener{
		conn:     conn,
		connDone: make(chan struct{}),
		stopped:  make(chan struct{}),
		addr:     conn.LocalAddr(),
		wrap:     wrap,
	}
}

// Accept returns the wrapped connection on the first call.
// On subsequent calls it blocks until the connection closes or the listener
// is closed, then returns net.ErrClosed.
func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()

	if c != nil {
		var out net.Conn = &notifyConn{Conn: c, done: l.connDone}
		if l.wrap != nil {
			out = l.wrap(out)
		}
		return out, nil
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

// UnwrapOneConn returns the underlying net.Conn when conn is the session-end
// wrapper a OneConnListener applies in Accept; otherwise it returns conn
// unchanged. Protocol code needs this when it type-asserts the connection
// handed out by a protocol library (e.g. to find a *tls.Conn) -- the wrapper
// would otherwise hide the concrete type.
func UnwrapOneConn(conn net.Conn) net.Conn {
	if nc, ok := conn.(*notifyConn); ok {
		return nc.Conn
	}
	return conn
}
