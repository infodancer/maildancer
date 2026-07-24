package backend_test

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/backend"
	"github.com/infodancer/maildancer/internal/imapd/config"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
)

// selfSignedTLS returns a server tls.Config with a fresh self-signed cert.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "imaps.test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"imaps.test.local"},
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

// TestServeConn_ImapsAllowsLoginInsideTLS pins the implicit-TLS contract that
// broke in production (#199): go-imap detects TLS by asserting the accepted
// connection to a concrete *tls.Conn, so the one-conn listener's notify shim
// must sit inside the TLS layer, not around it. If the shim hides the TLS
// conn, the post-handshake capability set still carries LOGINDISABLED and no
// client can authenticate on port 993.
func TestServeConn_ImapsAllowsLoginInsideTLS(t *testing.T) {
	sm := &recoverySM{tokens: make(map[string]bool), uidValidity: 42}
	sock := filepath.Join(t.TempDir(), "sm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(srv, sm)
	pb.RegisterMailboxServiceServer(srv, sm)
	pb.RegisterFolderServiceServer(srv, sm)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	cfg := config.Default()
	cfg.Hostname = "imaps.test.local"
	cfg.SessionManager = config.SessionManagerConfig{Socket: sock}
	cfg.Listeners = nil

	stack, err := backend.NewStack(backend.StackConfig{Config: cfg, TLSConfig: selfSignedTLS(t)})
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
		_ = stack.ServeConn(c, config.ModeImaps)
	}()

	conn, err := tls.Dial("tcp", tcpLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if strings.Contains(greeting, "LOGINDISABLED") {
		t.Errorf("post-handshake greeting still advertises LOGINDISABLED: %q", greeting)
	}
	if strings.Contains(greeting, "STARTTLS") {
		t.Errorf("implicit-TLS greeting advertises STARTTLS: %q", greeting)
	}

	if _, err := conn.Write([]byte("a1 LOGIN alice@test.local testpass\r\n")); err != nil {
		t.Fatalf("write login: %v", err)
	}
	for {
		line, rerr := r.ReadString('\n')
		if rerr != nil {
			t.Fatalf("read login response: %v", rerr)
		}
		if !strings.HasPrefix(line, "a1 ") {
			continue
		}
		if !strings.HasPrefix(line, "a1 OK") {
			t.Fatalf("LOGIN inside TLS = %q, want a1 OK", strings.TrimSpace(line))
		}
		break
	}
}
