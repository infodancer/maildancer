package pop3_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/logging"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
)

// newSingleConnStack creates a minimal Stack (no listeners) backed by a mock
// session-manager for use with RunSingleConn tests.
func newSingleConnStack(t *testing.T) *pop3.Stack {
	t.Helper()

	// Start a mock session-manager gRPC server.
	smDir := t.TempDir()
	smSocket := smDir + "/sm.sock"
	smLn, err := net.Listen("unix", smSocket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	smSrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(smSrv, &smpb.UnimplementedSessionServiceServer{})
	pb.RegisterMailboxServiceServer(smSrv, &pb.UnimplementedMailboxServiceServer{})
	go func() { _ = smSrv.Serve(smLn) }()
	t.Cleanup(func() { smSrv.GracefulStop() })

	cfg := config.Default()
	cfg.Hostname = "single.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: smSocket}

	logger := logging.NewLogger("error")
	stack, err := pop3.NewStack(pop3.StackConfig{
		Config:    cfg,
		Collector: &metrics.NoopCollector{},
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

// pop3Pipe is a thin POP3 client stub that drives the server over net.Pipe.
type pop3Pipe struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *pop3Pipe) readLine() string {
	line, _ := c.r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func (c *pop3Pipe) send(cmd string) {
	_, _ = fmt.Fprintf(c.conn, "%s\r\n", cmd)
}

func (c *pop3Pipe) readGreeting() string {
	return c.readLine()
}

// TestRunSingleConn_SessionEndsAfterQuit verifies that RunSingleConn returns
// after the client sends QUIT — the server does not hang indefinitely.
func TestRunSingleConn_SessionEndsAfterQuit(t *testing.T) {
	t.Parallel()

	stack := newSingleConnStack(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		stack.RunSingleConn(serverConn, config.ModePop3, nil) //nolint:errcheck
		close(done)
	}()

	c := &pop3Pipe{conn: clientConn, r: bufio.NewReader(clientConn)}

	// Read greeting.
	greeting := c.readGreeting()
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("expected +OK greeting, got: %q", greeting)
	}

	// Send QUIT.
	c.send("QUIT")
	resp := c.readLine()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("expected +OK after QUIT, got: %q", resp)
	}
	_ = clientConn.Close()

	select {
	case <-done:
		// good: RunSingleConn returned after QUIT
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after QUIT")
	}
}

// TestRunSingleConn_NoSecondConn verifies that after the first connection is
// served, RunSingleConn returns rather than waiting for another connection.
func TestRunSingleConn_NoSecondConn(t *testing.T) {
	t.Parallel()

	stack := newSingleConnStack(t)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		stack.RunSingleConn(serverConn, config.ModePop3, nil) //nolint:errcheck
		close(done)
	}()

	// Abruptly close the client side; RunSingleConn should notice and return.
	_ = clientConn.Close()

	select {
	case <-done:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("RunSingleConn did not return within 5s after client disconnect")
	}
}

// TestRunSingleConn_ConcurrentSessions verifies that multiple independent
// RunSingleConn calls can run concurrently on the same Stack.
func TestRunSingleConn_ConcurrentSessions(t *testing.T) {
	t.Parallel()

	stack := newSingleConnStack(t)

	const n = 3
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serverConn, clientConn := net.Pipe()

			done := make(chan struct{})
			go func() {
				stack.RunSingleConn(serverConn, config.ModePop3, nil) //nolint:errcheck
				close(done)
			}()

			c := &pop3Pipe{conn: clientConn, r: bufio.NewReader(clientConn)}
			c.readGreeting()
			c.send("QUIT")
			c.readLine()
			_ = clientConn.Close()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Errorf("RunSingleConn did not return within 5s")
			}
		}()
	}
	wg.Wait()
}
