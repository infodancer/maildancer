package authoidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/auth/authoidc"
)

// healthzBody is the wire shape of the /healthz response.
type healthzBody struct {
	Status string `json:"status"`
	Loaded int    `json:"loaded"`
	Failed int    `json:"failed"`
}

func getHealthz(t *testing.T, handler http.Handler) (*httptest.ResponseRecorder, healthzBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body healthzBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode healthz body %q: %v", rr.Body.String(), err)
	}
	return rr, body
}

// TestHealthz_AllDomainsLoaded: with every domain loaded, /healthz reports
// 200 with status=ok and the loaded-domain count.
func TestHealthz_AllDomainsLoaded(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	domainsDir := filepath.Join(tmpDir, "domains")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	provisionDomain(t, domainsDir, "one.example")
	provisionDomain(t, domainsDir, "two.example")

	cfg := &authoidc.Config{
		Server: authoidc.ServerConfig{
			Listen:         ":0",
			DataDir:        dataDir,
			DomainDataPath: domainsDir,
			JWTTTLSec:      3600,
			SessionTTLSec:  604800,
		},
	}
	srv, err := authoidc.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	rr, body := getHealthz(t, srv.Handler())
	if rr.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	if body.Loaded != 2 {
		t.Errorf("loaded = %d, want 2", body.Loaded)
	}
	if body.Failed != 0 {
		t.Errorf("failed = %d, want 0", body.Failed)
	}
}

// TestHealthz_DegradedDomain: with one domain failed at startup, /healthz
// reports 503 with status=degraded and both counts. The route is
// internet-reachable through the reverse proxy, so the body must never leak
// which domain broke or why -- counts only.
func TestHealthz_DegradedDomain(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	domainsDir := filepath.Join(tmpDir, "domains")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	provisionDomain(t, domainsDir, "good.example")
	provisionDomain(t, domainsDir, "broken.example")
	if err := os.WriteFile(filepath.Join(domainsDir, "broken.example", "config.toml"),
		[]byte("this is not TOML ["), 0600); err != nil {
		t.Fatalf("corrupt config: %v", err)
	}

	cfg := &authoidc.Config{
		Server: authoidc.ServerConfig{
			Listen:         ":0",
			DataDir:        dataDir,
			DomainDataPath: domainsDir,
			JWTTTLSec:      3600,
			SessionTTLSec:  604800,
		},
	}
	srv, err := authoidc.New(cfg)
	if err != nil {
		t.Fatalf("New must start degraded, not fail: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	rr, body := getHealthz(t, srv.Handler())
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("healthz status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if body.Status != "degraded" {
		t.Errorf("status = %q, want %q", body.Status, "degraded")
	}
	if body.Loaded != 1 {
		t.Errorf("loaded = %d, want 1", body.Loaded)
	}
	if body.Failed != 1 {
		t.Errorf("failed = %d, want 1", body.Failed)
	}
	for _, leak := range []string{"broken.example", "good.example", "TOML", "toml"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Errorf("healthz body leaks %q: %s", leak, rr.Body.String())
		}
	}
}
