package backend

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/imapd/config"
)

func TestHandlerArgs_ForwardsTLSFlags(t *testing.T) {
	got := handlerArgs("/etc/imapd.toml", "/certs/tls.crt", "/certs/tls.key")
	want := []string{"protocol-handler", "--config", "/etc/imapd.toml",
		"--tls-cert", "/certs/tls.crt", "--tls-key", "/certs/tls.key"}
	if !slices.Equal(got, want) {
		t.Errorf("handlerArgs with TLS = %v, want %v", got, want)
	}

	got = handlerArgs("/etc/imapd.toml", "", "")
	want = []string{"protocol-handler", "--config", "/etc/imapd.toml"}
	if !slices.Equal(got, want) {
		t.Errorf("handlerArgs without TLS = %v, want %v", got, want)
	}
}

func TestHandlerEnv_ConnectionMetadata(t *testing.T) {
	env := handlerEnv("192.0.2.7", "imaps")
	var gotIP, gotMode, gotPath bool
	for _, kv := range env {
		switch {
		case kv == EnvClientIP+"=192.0.2.7":
			gotIP = true
		case kv == EnvListenerMode+"=imaps":
			gotMode = true
		case strings.HasPrefix(kv, "PATH="):
			gotPath = true
		}
	}
	if !gotIP || !gotMode {
		t.Errorf("handlerEnv missing connection metadata: %v", env)
	}
	if !gotPath {
		t.Errorf("handlerEnv did not inherit PATH: %v", env)
	}
}

func TestNewDispatcher_ImapsRequiresTLS(t *testing.T) {
	cfg := config.Default()
	cfg.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Mode: config.ModeImaps}}

	_, err := NewDispatcher(DispatcherConfig{
		Config:     cfg,
		ExecPath:   "/bin/true",
		ConfigPath: "/etc/imapd.toml",
	})
	if err == nil || !strings.Contains(err.Error(), "imaps requires tls") {
		t.Fatalf("want imaps-requires-TLS error, got %v", err)
	}
}

func TestNewDispatcher_TLSMaterialMustExist(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// key deliberately missing

	cfg := config.Default()
	cfg.TLS.CertFile = cert
	cfg.TLS.KeyFile = key

	_, err := NewDispatcher(DispatcherConfig{
		Config:     cfg,
		ExecPath:   "/bin/true",
		ConfigPath: "/etc/imapd.toml",
	})
	if err == nil || !strings.Contains(err.Error(), "tls material not readable") {
		t.Fatalf("want missing-TLS-material error, got %v", err)
	}
}

// TestStack_ServeConnImapsRequiresTLS verifies the child-side guard: an imaps
// connection cannot be served without TLS material.
func TestStack_ServeConnImapsRequiresTLS(t *testing.T) {
	s := &Stack{}
	c1, c2 := net.Pipe()
	defer c2.Close()
	if err := s.ServeConn(c1, config.ModeImaps); err == nil {
		t.Fatal("want error serving imaps without TLS config, got nil")
	}
}
