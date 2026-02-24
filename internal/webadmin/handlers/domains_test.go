package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestDomainHandler(t *testing.T) (*DomainHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30 * time.Minute)
	return NewDomainHandler(dir, store, slog.Default()), dir
}

// createTestDomain creates a domain directory with config and passwd.
func createTestDomain(t *testing.T, domainsPath, name string) {
	t.Helper()
	domainDir := filepath.Join(domainsPath, name)
	if err := os.MkdirAll(filepath.Join(domainDir, "keys"), 0o750); err != nil {
		t.Fatal(err)
	}
	config := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(config), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("# Users\nuser1:hash1:user1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestHandleListDomains_Empty(t *testing.T) {
	h, _ := newTestDomainHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/domains", nil)
	rr := httptest.NewRecorder()
	h.HandleListDomains(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var domains []DomainSummary
	if err := json.NewDecoder(rr.Body).Decode(&domains); err != nil {
		t.Fatal(err)
	}
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

func TestHandleListDomains_WithDomains(t *testing.T) {
	h, dir := newTestDomainHandler(t)
	createTestDomain(t, dir, "example.com")
	createTestDomain(t, dir, "other.org")

	req := httptest.NewRequest(http.MethodGet, "/api/domains", nil)
	rr := httptest.NewRecorder()
	h.HandleListDomains(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var domains []DomainSummary
	if err := json.NewDecoder(rr.Body).Decode(&domains); err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
}

func TestHandleGetDomain(t *testing.T) {
	h, dir := newTestDomainHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleGetDomain(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var detail DomainDetail
	if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Name != "example.com" {
		t.Errorf("expected name example.com, got %s", detail.Name)
	}
	if detail.AuthType != "passwd" {
		t.Errorf("expected auth type passwd, got %s", detail.AuthType)
	}
	if detail.StoreType != "maildir" {
		t.Errorf("expected store type maildir, got %s", detail.StoreType)
	}
	if detail.UserCount != 1 {
		t.Errorf("expected 1 user, got %d", detail.UserCount)
	}
}

func TestHandleGetDomain_NotFound(t *testing.T) {
	h, _ := newTestDomainHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/domains/missing.com", nil)
	req.SetPathValue("name", "missing.com")
	rr := httptest.NewRecorder()
	h.HandleGetDomain(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetDomain_InvalidName(t *testing.T) {
	h, _ := newTestDomainHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/domains/../etc", nil)
	req.SetPathValue("name", "../etc")
	rr := httptest.NewRecorder()
	h.HandleGetDomain(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCreateDomain(t *testing.T) {
	h, dir := newTestDomainHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "new.example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleCreateDomain(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify directory was created
	domainDir := filepath.Join(dir, "new.example.com")
	if !dirExists(domainDir) {
		t.Error("expected domain directory to exist")
	}
	if !dirExists(filepath.Join(domainDir, "keys")) {
		t.Error("expected keys directory to exist")
	}
	if _, err := os.Stat(filepath.Join(domainDir, "config.toml")); err != nil {
		t.Error("expected config.toml to exist")
	}
	if _, err := os.Stat(filepath.Join(domainDir, "passwd")); err != nil {
		t.Error("expected passwd file to exist")
	}
}

func TestHandleCreateDomain_AlreadyExists(t *testing.T) {
	h, dir := newTestDomainHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]string{"name": "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleCreateDomain(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestHandleCreateDomain_InvalidName(t *testing.T) {
	h, _ := newTestDomainHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "../escape"})
	req := httptest.NewRequest(http.MethodPost, "/api/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleCreateDomain(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleDeleteDomain_RequiresConfirmation(t *testing.T) {
	h, dir := newTestDomainHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleDeleteDomain(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 (requires confirmation), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteDomain_WithConfirmation(t *testing.T) {
	h, dir := newTestDomainHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com?confirm=true", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleDeleteDomain(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	domainDir := filepath.Join(dir, "example.com")
	if dirExists(domainDir) {
		t.Error("expected domain directory to be removed")
	}
}

func TestHandleDeleteDomain_NotFound(t *testing.T) {
	h, _ := newTestDomainHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/missing.com", nil)
	req.SetPathValue("name", "missing.com")
	rr := httptest.NewRecorder()
	h.HandleDeleteDomain(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestIsValidDomainName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"example.com", true},
		{"mail.example.com", true},
		{"sub.domain.example.org", true},
		{"a.bc", true},
		{"", false},
		{"../etc", false},
		{"/etc/passwd", false},
		{"single", false},
		{"-start.com", false},
		{"end-.com", false},
		{"UPPER.COM", false},
		{"has spaces.com", false},
		{"has_underscore.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDomainName(tt.name); got != tt.valid {
				t.Errorf("isValidDomainName(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

func TestExtractTOMLValue(t *testing.T) {
	content := `[auth]
type = "passwd"
credential_backend = "passwd"

[msgstore]
type = "maildir"
base_path = "users"
`
	if got := extractTOMLValue(content, "type", "auth"); got != "passwd" {
		t.Errorf("expected 'passwd', got %q", got)
	}
	if got := extractTOMLValue(content, "type", "msgstore"); got != "maildir" {
		t.Errorf("expected 'maildir', got %q", got)
	}
	if got := extractTOMLValue(content, "missing", "auth"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
