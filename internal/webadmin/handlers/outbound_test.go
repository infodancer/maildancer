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

func newTestOutboundHandler(t *testing.T) (*OutboundHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30*time.Minute, false)
	return NewOutboundHandler(dir, store, slog.Default(), nil), dir
}

func TestGetDomainOutbound_NoConfig(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	// Remove outbound section from config (default config has none).
	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/outbound", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleGetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp outboundResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Strategy != "" {
		t.Errorf("expected empty strategy, got %q", resp.Strategy)
	}
	if resp.HasPassword {
		t.Error("expected has_password false")
	}
}

func TestGetDomainOutbound_SmarthostConfig(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	domainDir := filepath.Join(dir, "example.com")

	// Add outbound section to config.
	configPath := filepath.Join(domainDir, "config.toml")
	data, _ := os.ReadFile(configPath)
	outbound := string(data) + `
[outbound]
strategy = "smarthost"
smarthost = "relay.example.com:587"
smarthost_user = "apiuser"
password_file = "outbound-password"
`
	if err := os.WriteFile(configPath, []byte(outbound), 0o640); err != nil {
		t.Fatal(err)
	}
	// Write password file.
	if err := os.WriteFile(filepath.Join(domainDir, "outbound-password"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/outbound", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleGetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp outboundResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Strategy != "smarthost" {
		t.Errorf("expected strategy smarthost, got %q", resp.Strategy)
	}
	if resp.Smarthost != "relay.example.com:587" {
		t.Errorf("expected smarthost relay.example.com:587, got %q", resp.Smarthost)
	}
	if resp.SmarthostUser != "apiuser" {
		t.Errorf("expected smarthost_user apiuser, got %q", resp.SmarthostUser)
	}
	if !resp.HasPassword {
		t.Error("expected has_password true")
	}
	if resp.PasswordFile != "outbound-password" {
		t.Errorf("expected password_file outbound-password, got %q", resp.PasswordFile)
	}
}

func TestSetDomainOutbound_Smarthost(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(outboundRequest{
		Strategy:      "smarthost",
		Smarthost:     "smtp.relay.com:587",
		SmarthostUser: "user@relay.com",
		Password:      "s3cret",
		PasswordFile:  "outbound-password",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
	req.SetPathValue("name", "example.com")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleSetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify config was written.
	domainDir := filepath.Join(dir, "example.com")
	configData, err := os.ReadFile(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(configData)
	if v := extractTOMLValue(content, "strategy", "outbound"); v != "smarthost" {
		t.Errorf("expected strategy smarthost in config, got %q", v)
	}
	if v := extractTOMLValue(content, "smarthost", "outbound"); v != "smtp.relay.com:587" {
		t.Errorf("expected smarthost smtp.relay.com:587, got %q", v)
	}

	// Verify password file.
	pwData, err := os.ReadFile(filepath.Join(domainDir, "outbound-password"))
	if err != nil {
		t.Fatal("password file not written:", err)
	}
	if string(pwData) != "s3cret\n" {
		t.Errorf("unexpected password file content: %q", pwData)
	}

	// Verify password file permissions (0600).
	info, err := os.Stat(filepath.Join(domainDir, "outbound-password"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected password file mode 0600, got %04o", perm)
	}
}

func TestSetDomainOutbound_Direct(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	domainDir := filepath.Join(dir, "example.com")

	// First set up smarthost config with password file.
	configPath := filepath.Join(domainDir, "config.toml")
	data, _ := os.ReadFile(configPath)
	withOutbound := string(data) + `
[outbound]
strategy = "smarthost"
smarthost = "relay.example.com:587"
smarthost_user = "user"
password_file = "outbound-password"
`
	if err := os.WriteFile(configPath, []byte(withOutbound), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "outbound-password"), []byte("old-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Switch to direct.
	body, _ := json.Marshal(outboundRequest{Strategy: "direct"})
	req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
	req.SetPathValue("name", "example.com")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleSetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify outbound keys cleared.
	configData, _ := os.ReadFile(configPath)
	content := string(configData)
	if v := extractTOMLValue(content, "strategy", "outbound"); v != "" {
		t.Errorf("expected strategy cleared, got %q", v)
	}

	// Verify password file removed.
	if _, err := os.Stat(filepath.Join(domainDir, "outbound-password")); !os.IsNotExist(err) {
		t.Error("expected password file to be removed")
	}
}

func TestSetDomainOutbound_PreservesOtherSections(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(outboundRequest{
		Strategy:      "smarthost",
		Smarthost:     "relay.example.com:587",
		SmarthostUser: "user",
		Password:      "secret",
		PasswordFile:  "outbound-password",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
	req.SetPathValue("name", "example.com")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleSetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify [auth] and [msgstore] are untouched.
	configData, _ := os.ReadFile(filepath.Join(dir, "example.com", "config.toml"))
	content := string(configData)
	if v := extractTOMLValue(content, "type", "auth"); v != "passwd" {
		t.Errorf("expected auth type passwd, got %q", v)
	}
	if v := extractTOMLValue(content, "type", "msgstore"); v != "maildir" {
		t.Errorf("expected msgstore type maildir, got %q", v)
	}
}

func TestSetDomainOutbound_PasswordPreserved(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	domainDir := filepath.Join(dir, "example.com")

	// Set up initial smarthost config with password.
	configPath := filepath.Join(domainDir, "config.toml")
	data, _ := os.ReadFile(configPath)
	withOutbound := string(data) + `
[outbound]
strategy = "smarthost"
smarthost = "relay.example.com:587"
smarthost_user = "user"
password_file = "outbound-password"
`
	if err := os.WriteFile(configPath, []byte(withOutbound), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "outbound-password"), []byte("existing-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Update without providing a new password (empty password = keep existing).
	body, _ := json.Marshal(outboundRequest{
		Strategy:      "smarthost",
		Smarthost:     "new-relay.example.com:587",
		SmarthostUser: "newuser",
		Password:      "", // empty = keep existing
		PasswordFile:  "outbound-password",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
	req.SetPathValue("name", "example.com")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleSetDomainOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify password file is unchanged.
	pwData, err := os.ReadFile(filepath.Join(domainDir, "outbound-password"))
	if err != nil {
		t.Fatal("password file should still exist:", err)
	}
	if string(pwData) != "existing-secret\n" {
		t.Errorf("password file content changed: %q", pwData)
	}

	// Verify config was updated.
	configData, _ := os.ReadFile(configPath)
	if v := extractTOMLValue(string(configData), "smarthost", "outbound"); v != "new-relay.example.com:587" {
		t.Errorf("expected updated smarthost, got %q", v)
	}
}

func TestSetDomainOutbound_PathTraversalRejected(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	cases := []string{"../etc/passwd", "sub/file", "back\\slash"}
	for _, pwFile := range cases {
		body, _ := json.Marshal(outboundRequest{
			Strategy:      "smarthost",
			Smarthost:     "relay.example.com:587",
			SmarthostUser: "user",
			Password:      "secret",
			PasswordFile:  pwFile,
		})
		req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
		req.SetPathValue("name", "example.com")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandleSetDomainOutbound(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("password_file=%q: expected 400, got %d", pwFile, rr.Code)
		}
	}
}

func TestSetDomainOutbound_ValidationRequiresFields(t *testing.T) {
	h, dir := newTestOutboundHandler(t)
	createTestDomain(t, dir, "example.com")

	cases := []struct {
		name string
		req  outboundRequest
	}{
		{
			name: "smarthost without host",
			req:  outboundRequest{Strategy: "smarthost", SmarthostUser: "user", PasswordFile: "pw"},
		},
		{
			name: "smarthost without user",
			req:  outboundRequest{Strategy: "smarthost", Smarthost: "relay:587", PasswordFile: "pw"},
		},
		{
			name: "smarthost without password_file",
			req:  outboundRequest{Strategy: "smarthost", Smarthost: "relay:587", SmarthostUser: "user"},
		},
		{
			name: "smarthost missing port",
			req:  outboundRequest{Strategy: "smarthost", Smarthost: "relay", SmarthostUser: "user", PasswordFile: "pw"},
		},
		{
			name: "invalid strategy",
			req:  outboundRequest{Strategy: "invalid"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.req)
			req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/outbound", bytes.NewReader(body))
			req.SetPathValue("name", "example.com")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.HandleSetDomainOutbound(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestGetDefaultOutbound(t *testing.T) {
	h, dir := newTestOutboundHandler(t)

	// Write system-wide config with outbound section.
	configContent := `[outbound]
strategy = "direct"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(configContent), 0o640); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/outbound/default", nil)
	rr := httptest.NewRecorder()
	h.HandleGetDefaultOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp outboundResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Strategy != "direct" {
		t.Errorf("expected strategy direct, got %q", resp.Strategy)
	}
}

func TestSetDefaultOutbound(t *testing.T) {
	h, dir := newTestOutboundHandler(t)

	body, _ := json.Marshal(outboundRequest{
		Strategy:      "smarthost",
		Smarthost:     "global-relay.example.com:587",
		SmarthostUser: "globaluser",
		Password:      "globalsecret",
		PasswordFile:  "global-password",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/outbound/default", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleSetDefaultOutbound(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify system config.
	configData, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(configData)
	if v := extractTOMLValue(content, "strategy", "outbound"); v != "smarthost" {
		t.Errorf("expected strategy smarthost, got %q", v)
	}

	// Verify password file.
	pwData, err := os.ReadFile(filepath.Join(dir, "global-password"))
	if err != nil {
		t.Fatal("password file not written:", err)
	}
	if string(pwData) != "globalsecret\n" {
		t.Errorf("unexpected password content: %q", pwData)
	}
}
