package smtp_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	smtpserver "github.com/infodancer/maildancer/internal/smtpd/smtp"
	"google.golang.org/grpc"
)

// tlsCountingCollector counts TLS establishments and signals session end, so
// tests can wait for the session to finish rather than sleeping. Only the
// methods these tests exercise do anything; the rest satisfy the interface.
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

// waitClosed blocks until the session reports its connection closed.
func (c *tlsCountingCollector) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("session did not close within 10s")
	}
}

// selfSignedSMTPTLS returns a server tls.Config with a fresh self-signed cert.
func selfSignedSMTPTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "single.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"single.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}}}
}

// newTLSMetricsEnv builds a Server wired to a counting collector, with the
// given listener mode and TLS config. It mirrors newSingleConnEnv but needs
// its own copy because the collector and TLS config must reach the Backend and
// the go-smtp server respectively.
func newTLSMetricsEnv(t *testing.T, mode config.ListenerMode, tlsCfg *tls.Config) (*smtpserver.Server, *tlsCountingCollector) {
	t.Helper()

	socketPath := t.TempDir() + "/sm.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, &mockSCDeliveryServer{})
	smpb.RegisterSessionServiceServer(gsrv, &mockSCSessionServer{
		localDomains: map[string]bool{"single.local": true},
	})
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	smDelivery, err := smtpserver.NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("NewSessionManagerDeliveryAgent: %v", err)
	}
	t.Cleanup(func() { _ = smDelivery.Close() })

	collector := newTLSCountingCollector()
	backend := smtpserver.NewBackend(smtpserver.BackendConfig{
		Hostname:       "single.local",
		SMDelivery:     smDelivery,
		MaxRecipients:  10,
		MaxMessageSize: 10 * 1024 * 1024,
		TempDir:        t.TempDir(),
		Collector:      collector,
	})

	srv, err := smtpserver.NewServer(smtpserver.ServerConfig{
		Backend: backend,
		Listeners: []config.ListenerConfig{
			{Address: "127.0.0.1:0", Mode: mode},
		},
		Hostname:       "single.local",
		TLSConfig:      tlsCfg,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, collector
}

// serveOneTLSMetricsConn accepts a single connection on a loopback listener and
// serves it via RunSingleConn, returning the address to dial.
func serveOneTLSMetricsConn(t *testing.T, srv *smtpserver.Server, mode config.ListenerMode, tlsCfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_ = srv.RunSingleConn(conn, mode, tlsCfg)
	}()
	return ln.Addr().String()
}

// readSMTPReply reads one (possibly multiline) SMTP reply.
func readSMTPReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		b.WriteString(line)
		// Continuation lines have a '-' in the fourth column.
		if len(line) < 4 || line[3] != '-' {
			return b.String()
		}
	}
}

// TestRunSingleConn_SmtpsCountsTLSConnection pins the fix for #207: implicit
// TLS on the SMTPS port must increment smtpd_tls_connections_total. Before the
// fix the metric was registered and scraped but never written, so it read 0
// against a listener carrying nothing but TLS.
func TestRunSingleConn_SmtpsCountsTLSConnection(t *testing.T) {
	tlsCfg := selfSignedSMTPTLS(t)
	srv, collector := newTLSMetricsEnv(t, config.ModeSmtps, tlsCfg)
	addr := serveOneTLSMetricsConn(t, srv, config.ModeSmtps, tlsCfg)

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	if greeting := readSMTPReply(t, r); !strings.HasPrefix(greeting, "220") {
		t.Fatalf("greeting = %q, want 220", strings.TrimSpace(greeting))
	}
	// EHLO is required: go-smtp creates the Session lazily, so a connection
	// that never greets produces no Logout and no session-end metrics at all.
	if _, err := conn.Write([]byte("EHLO client.test\r\n")); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	readSMTPReply(t, r)
	if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatalf("write QUIT: %v", err)
	}
	readSMTPReply(t, r)
	_ = conn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 1 {
		t.Errorf("TLSConnectionEstablished calls = %d, want 1", got)
	}
}

// TestRunSingleConn_StarttlsCountsTLSConnection pins the STARTTLS half of
// #207. go-smtp performs the upgrade internally, so there is no callback to
// hang the counter on; the session must observe its own TLS state instead.
func TestRunSingleConn_StarttlsCountsTLSConnection(t *testing.T) {
	tlsCfg := selfSignedSMTPTLS(t)
	srv, collector := newTLSMetricsEnv(t, config.ModeSmtp, tlsCfg)
	addr := serveOneTLSMetricsConn(t, srv, config.ModeSmtp, tlsCfg)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(raw)
	if greeting := readSMTPReply(t, r); !strings.HasPrefix(greeting, "220") {
		t.Fatalf("greeting = %q, want 220", strings.TrimSpace(greeting))
	}
	if _, err := raw.Write([]byte("EHLO client.test\r\n")); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	if ehlo := readSMTPReply(t, r); !strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO response does not advertise STARTTLS: %q", ehlo)
	}
	if _, err := raw.Write([]byte("STARTTLS\r\n")); err != nil {
		t.Fatalf("write STARTTLS: %v", err)
	}
	if reply := readSMTPReply(t, r); !strings.HasPrefix(reply, "220") {
		t.Fatalf("STARTTLS reply = %q, want 220", strings.TrimSpace(reply))
	}

	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tr := bufio.NewReader(tconn)
	if _, err := tconn.Write([]byte("EHLO client.test\r\n")); err != nil {
		t.Fatalf("write EHLO inside TLS: %v", err)
	}
	readSMTPReply(t, tr)
	if _, err := tconn.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatalf("write QUIT: %v", err)
	}
	readSMTPReply(t, tr)
	_ = tconn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 1 {
		t.Errorf("TLSConnectionEstablished calls = %d, want 1", got)
	}
}

// TestRunSingleConn_PlaintextCountsNoTLSConnection guards the other direction:
// a cleartext session must not increment the TLS counter. Without this, a fix
// that counted every session would look correct in the two tests above.
func TestRunSingleConn_PlaintextCountsNoTLSConnection(t *testing.T) {
	srv, collector := newTLSMetricsEnv(t, config.ModeSmtp, nil)
	addr := serveOneTLSMetricsConn(t, srv, config.ModeSmtp, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	readSMTPReply(t, r)
	if _, err := conn.Write([]byte("EHLO client.test\r\n")); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	readSMTPReply(t, r)
	if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatalf("write QUIT: %v", err)
	}
	readSMTPReply(t, r)
	_ = conn.Close()

	collector.waitClosed(t)
	if got := collector.tlsCount(); got != 0 {
		t.Errorf("TLSConnectionEstablished calls = %d on a cleartext session, want 0", got)
	}
}
