package authoidc_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/internal/auth/authoidc"
	"github.com/infodancer/maildancer/auth/passwd"
)

// provisionDomain lays down a complete on-disk domain (config.toml + passwd +
// empty keys dir) under root/<domain>, the way the mail stack provisions an
// owned domain. It registers no OIDC client.
func provisionDomain(t *testing.T, root, domain string) {
	t.Helper()
	domainDir := filepath.Join(root, domain)
	keyDir := filepath.Join(domainDir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("mkdir %s: %v", keyDir, err)
	}
	cfg := "[auth]\ntype = \"passwd\"\ncredential_backend = \"passwd\"\nkey_backend = \"keys\"\n"
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0600); err != nil {
		t.Fatalf("write domain config: %v", err)
	}
	if err := passwd.AddUser(filepath.Join(domainDir, "passwd"), "alice", "s3cr3t"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
}

// TestNew_LoadsDomainsFromDataPath_WithoutClients pins the design invariant
// (oidc-federation-design.md): the set of served domains comes from the
// directories under domain_data_path, NOT from static [[client]] config.
// Registration is open (RFC 7591), so a domain with no configured client must
// still answer webfinger/discovery. Regression guard for the bug where New()
// only loaded domains referenced by cfg.Clients (auth#57).
func TestNew_LoadsDomainsFromDataPath_WithoutClients(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	domainsDir := filepath.Join(tmpDir, "domains")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	provisionDomain(t, domainsDir, "noclient.example")

	cfg := &authoidc.Config{
		Server: authoidc.ServerConfig{
			Listen:         ":0",
			DataDir:        dataDir,
			DomainDataPath: domainsDir,
			JWTTTLSec:      3600,
			SessionTTLSec:  604800,
		},
		// Deliberately no Clients: domain availability must not depend on them.
	}
	srv, err := authoidc.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/webfinger?resource=acct:_@noclient.example", nil)
	req.Host = "noclient.example"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("webfinger status = %d, want 200 — domain should load from domain_data_path "+
			"without a [[client]] entry; body=%s", rr.Code, rr.Body.String())
	}
}

// TestNew_MultipleDataPathDomains_AllServed confirms every provisioned domain
// loads, not just one, and that a non-domain directory entry is skipped.
func TestNew_MultipleDataPathDomains_AllServed(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	domainsDir := filepath.Join(tmpDir, "domains")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	for _, d := range []string{"one.example", "two.example"} {
		provisionDomain(t, domainsDir, d)
	}
	// A stray directory with no config.toml (e.g. "postmaster") must be ignored,
	// not abort startup.
	if err := os.MkdirAll(filepath.Join(domainsDir, "postmaster"), 0700); err != nil {
		t.Fatalf("mkdir stray: %v", err)
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
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	handler := srv.Handler()

	for _, d := range []string{"one.example", "two.example"} {
		req := httptest.NewRequest(http.MethodGet,
			"/.well-known/webfinger?resource=acct:_@"+d, nil)
		req.Host = d
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("webfinger(%s) status = %d, want 200; body=%s", d, rr.Code, rr.Body.String())
		}
	}
}
