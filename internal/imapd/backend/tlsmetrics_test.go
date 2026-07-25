package backend_test

import (
	"bufio"
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
)

// tlsCountingCollector counts TLS establishments and signals session end, so
// tests can wait for the session to finish rather than sleeping.
type tlsCountingCollector struct {
	metrics.NoopCollector

	mu     sync.Mutex
	tls    int
	closed chan struct{}
	once   sync.Once
}

func newTLSCountingCollector() *tlsCountingCollector {
	return &tlsCountingCollector{closed: make(chan struct{})}
}

func (c *tlsCountingCollector) TLSConnectionEstablished() {
	c.mu.Lock()
	c.tls++
	c.mu.Unlock()
}

func (c *tlsCountingCollector) ConnectionClosed() {
	c.once.Do(func() { close(c.closed) })
}

func (c *tlsCountingCollector) tlsCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tls
}

func (c *tlsCountingCollector) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("session did not close within 10s")
	}
}

// newTLSMetricsStack builds a Stack wired to a counting collector and serves
// exactly one connection in the given mode, returning the address to dial.
func newTLSMetricsStack(t *testing.T, mode config.ListenerMode, tlsCfg *tls.Config) (string, *tlsCountingCollector) {
	t.Helper()

	sm := newRecoverySM()
	sock := filepath.Join(t.TempDir(), "sm.sock")
	smLn, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	gsrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(gsrv, sm)
	pb.RegisterMailboxServiceServer(gsrv, sm)
	pb.RegisterFolderServiceServer(gsrv, sm)
	go func() { _ = gsrv.Serve(smLn) }()
	t.Cleanup(gsrv.Stop)

	cfg := config.Default()
	cfg.Hostname = "imaps.test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = nil

	collector := newTLSCountingCollector()
	stack, err := backend.NewStack(backend.StackConfig{
		Config:    cfg,
		TLSConfig: tlsCfg,
		Collector: collector,
	})
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		c, aerr := tcpLn.Accept()
		if aerr != nil {
			return
		}
		_ = stack.ServeConn(c, mode)
	}()

	return tcpLn.Addr().String(), collector
}

// readTaggedResponse reads until the line tagged with tag, returning it.
func readTaggedResponse(t *testing.T, r *bufio.Reader, tag string) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s response: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return line
		}
	}
}

// TestServeConn_ImapsCountsTLSConnection pins the fix for #207: implicit TLS on
// port 993 must increment imapd_tls_connections_total. Before the fix the
// metric was registered and scraped but never written, so it read 0 against
// 2165 connections that were effectively all TLS.
func TestServeConn_ImapsCountsTLSConnection(t *testing.T) {
	tlsCfg := selfSignedTLS(t)
	addr, collector := newTLSMetricsStack(t, config.ModeImaps, tlsCfg)

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if _, err := conn.Write([]byte("a1 LOGOUT\r\n")); err != nil {
		t.Fatalf("write LOGOUT: %v", err)
	}
	readTaggedResponse(t, r, "a1")
	_ = conn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 1 {
		t.Errorf("TLSConnectionEstablished calls = %d, want 1", got)
	}
}

// TestServeConn_StarttlsCountsTLSConnection pins the STARTTLS half of #207.
// go-imap performs the upgrade internally with no callback, and it keeps the
// same Session across the upgrade, so the count has to come from the session
// observing its own transport.
func TestServeConn_StarttlsCountsTLSConnection(t *testing.T) {
	tlsCfg := selfSignedTLS(t)
	addr, collector := newTLSMetricsStack(t, config.ModeImap, tlsCfg)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(raw)
	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "STARTTLS") {
		t.Fatalf("cleartext greeting does not advertise STARTTLS: %q", greeting)
	}
	if _, err := raw.Write([]byte("a1 STARTTLS\r\n")); err != nil {
		t.Fatalf("write STARTTLS: %v", err)
	}
	if resp := readTaggedResponse(t, r, "a1"); !strings.HasPrefix(resp, "a1 OK") {
		t.Fatalf("STARTTLS = %q, want a1 OK", strings.TrimSpace(resp))
	}

	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tr := bufio.NewReader(tconn)
	if _, err := tconn.Write([]byte("a2 LOGOUT\r\n")); err != nil {
		t.Fatalf("write LOGOUT: %v", err)
	}
	readTaggedResponse(t, tr, "a2")
	_ = tconn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 1 {
		t.Errorf("TLSConnectionEstablished calls = %d, want 1", got)
	}
}

// TestServeConn_PlaintextCountsNoTLSConnection guards the other direction: a
// cleartext session must not increment the TLS counter. Without it, a fix that
// counted every session would pass the two tests above.
func TestServeConn_PlaintextCountsNoTLSConnection(t *testing.T) {
	addr, collector := newTLSMetricsStack(t, config.ModeImap, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if _, err := conn.Write([]byte("a1 LOGOUT\r\n")); err != nil {
		t.Fatalf("write LOGOUT: %v", err)
	}
	readTaggedResponse(t, r, "a1")
	_ = conn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 0 {
		t.Errorf("TLSConnectionEstablished calls = %d on a cleartext session, want 0", got)
	}
}
