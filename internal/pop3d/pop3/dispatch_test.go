package pop3

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

func TestHandlerArgs_ForwardsTLSFlags(t *testing.T) {
	got := handlerArgs("/etc/pop3d.toml", "/certs/tls.crt", "/certs/tls.key")
	want := []string{"protocol-handler", "--config", "/etc/pop3d.toml",
		"--tls-cert", "/certs/tls.crt", "--tls-key", "/certs/tls.key"}
	if !slices.Equal(got, want) {
		t.Errorf("handlerArgs with TLS = %v, want %v", got, want)
	}

	got = handlerArgs("/etc/pop3d.toml", "", "")
	want = []string{"protocol-handler", "--config", "/etc/pop3d.toml"}
	if !slices.Equal(got, want) {
		t.Errorf("handlerArgs without TLS = %v, want %v", got, want)
	}
}

func TestHandlerEnv_ConnectionMetadata(t *testing.T) {
	env := handlerEnv("192.0.2.7", "pop3s")
	var gotIP, gotMode, gotPath bool
	for _, kv := range env {
		switch {
		case kv == EnvClientIP+"=192.0.2.7":
			gotIP = true
		case kv == EnvListenerMode+"=pop3s":
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

func TestNewDispatcher_Pop3sRequiresTLS(t *testing.T) {
	cfg := config.Default()
	cfg.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Mode: config.ModePop3s}}

	_, err := NewDispatcher(DispatcherConfig{
		Config:     cfg,
		ExecPath:   "/bin/true",
		ConfigPath: "/etc/pop3d.toml",
	})
	if err == nil || !strings.Contains(err.Error(), "pop3s requires tls") {
		t.Fatalf("want pop3s-requires-TLS error, got %v", err)
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
		ConfigPath: "/etc/pop3d.toml",
	})
	if err == nil || !strings.Contains(err.Error(), "tls material not readable") {
		t.Fatalf("want missing-TLS-material error, got %v", err)
	}
}

// TestRunSingleConn_Pop3sRequiresTLS verifies the child-side guard: a pop3s
// connection cannot be served without TLS material.
func TestRunSingleConn_Pop3sRequiresTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.Hostname = "tlsguard.local"
	srv, err := server.New(server.Config{Cfg: &cfg, Logger: logger})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	s := &Stack{server: srv, logger: logger}

	c1, c2 := net.Pipe()
	defer c2.Close()
	if err := s.RunSingleConn(c1, config.ModePop3s); err == nil {
		t.Fatal("want error serving pop3s without TLS config, got nil")
	}
}

func TestHandlerSysProcAttr(t *testing.T) {
	cfg := config.Default()
	if got := handlerSysProcAttr(cfg); got != nil {
		t.Errorf("zero handler_uid must not drop credentials, got %+v", got)
	}

	cfg.HandlerUID = 902
	cfg.HandlerGID = 903
	cfg.HandlerGroups = []uint32{904}
	attr := handlerSysProcAttr(cfg)
	if attr == nil || attr.Credential == nil {
		t.Fatalf("handler_uid set: want credential drop, got %+v", attr)
	}
	if attr.Credential.Uid != 902 || attr.Credential.Gid != 903 ||
		len(attr.Credential.Groups) != 1 || attr.Credential.Groups[0] != 904 {
		t.Errorf("wrong credentials: %+v", attr.Credential)
	}
	if !attr.Setpgid {
		t.Error("dropped handlers must get their own process group")
	}
}
