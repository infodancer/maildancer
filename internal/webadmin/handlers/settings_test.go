package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestSettingsHandler(t *testing.T) (*SettingsHandler, string) {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "shared.toml")
	store := session.NewStore(30 * time.Minute, false)
	return NewSettingsHandler(cfgFile, store, slog.Default()), cfgFile
}

// writeConfig writes content to the config file used by the handler.
func writeConfig(t *testing.T, cfgFile, content string) {
	t.Helper()
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

const fullSharedConfig = `# shared config

[server]
hostname = "mail.example.com"
maildir = "/var/mail"

[smtpd]
log_level = "info"

[smtpd.limits]
max_message_size = 26214400
max_recipients = 100

[pop3d]
log_level = "warn"

[pop3d.limits]
max_connections = 50

[spamcheck]
enabled = true
`

func TestHandleGetSettings_NoFile(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	_ = os.Remove(cfgFile)

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	h.HandleGetSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Sections should be present with zero values.
	if _, ok := resp["server"]; !ok {
		t.Error("expected server section in response")
	}
	if _, ok := resp["smtpd"]; !ok {
		t.Error("expected smtpd section in response")
	}
}

func TestHandleGetSettings_ReturnsValues(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	h.HandleGetSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	server, _ := resp["server"].(map[string]any)
	if server["hostname"] != "mail.example.com" {
		t.Errorf("hostname: got %v", server["hostname"])
	}
	if server["maildir"] != "/var/mail" {
		t.Errorf("maildir: got %v", server["maildir"])
	}

	smtpd, _ := resp["smtpd"].(map[string]any)
	if smtpd["log_level"] != "info" {
		t.Errorf("smtpd.log_level: got %v", smtpd["log_level"])
	}
	limits, _ := smtpd["limits"].(map[string]any)
	if limits["max_message_size"] != float64(26214400) {
		t.Errorf("max_message_size: got %v", limits["max_message_size"])
	}

	pop3d, _ := resp["pop3d"].(map[string]any)
	if pop3d["log_level"] != "warn" {
		t.Errorf("pop3d.log_level: got %v", pop3d["log_level"])
	}

	spamcheck, _ := resp["spamcheck"].(map[string]any)
	if spamcheck["enabled"] != true {
		t.Errorf("spamcheck.enabled: got %v", spamcheck["enabled"])
	}
}

func TestHandleSetServerSettings_UpdatesHostname(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"hostname":"new.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/server", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetServerSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check file was updated.
	data, _ := os.ReadFile(cfgFile)
	s := string(data)
	if !strings.Contains(s, `hostname = "new.example.com"`) {
		t.Errorf("expected updated hostname in file, got:\n%s", s)
	}
	if strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected old hostname replaced, got:\n%s", s)
	}
	// Other content preserved.
	if !strings.Contains(s, `maildir = "/var/mail"`) {
		t.Errorf("expected maildir preserved, got:\n%s", s)
	}
	if !strings.Contains(s, "# shared config") {
		t.Errorf("expected comment preserved, got:\n%s", s)
	}
}

func TestHandleSetSmtpdSettings_UpdatesLogLevel(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"log_level":"debug"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/smtpd", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetSmtpdSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(cfgFile)
	s := string(data)
	if !strings.Contains(s, `log_level = "debug"`) {
		t.Errorf("expected updated smtpd log_level, got:\n%s", s)
	}
}

func TestHandleSetPop3dSettings_UpdatesLogLevel(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"log_level":"error"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/pop3d", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetPop3dSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(cfgFile)
	s := string(data)
	if !strings.Contains(s, `log_level = "error"`) {
		t.Errorf("expected updated pop3d log_level, got:\n%s", s)
	}
	// smtpd log_level unchanged
	if !strings.Contains(s, `[smtpd]`) {
		t.Errorf("expected [smtpd] section preserved")
	}
}

func TestHandleSetSpamcheckSettings_TogglesEnabled(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"enabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/spamcheck", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetSpamcheckSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(cfgFile)
	s := string(data)
	if !strings.Contains(s, "enabled = false") {
		t.Errorf("expected enabled = false, got:\n%s", s)
	}
}

func TestHandleSettings_NoFileConfigured_Returns400(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	h := NewSettingsHandler("", store, slog.Default())

	body := `{"hostname":"x.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/server", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetServerSettings(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when no file configured, got %d", w.Code)
	}
}

func TestHandleSettings_InvalidJSON_Returns400(t *testing.T) {
	h, _ := newTestSettingsHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/settings/server", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	h.HandleSetServerSettings(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleSettings_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "shared.toml")
	writeConfig(t, cfgFile, fullSharedConfig)
	store := session.NewStore(30 * time.Minute, false)

	h1 := NewSettingsHandler(cfgFile, store, slog.Default())
	body := `{"hostname":"persist.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/server", strings.NewReader(body))
	h1.HandleSetServerSettings(httptest.NewRecorder(), req)

	// New handler instance reads the same file.
	h2 := NewSettingsHandler(cfgFile, store, slog.Default())
	req2 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w2 := httptest.NewRecorder()
	h2.HandleGetSettings(w2, req2)

	var resp map[string]any
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	server, _ := resp["server"].(map[string]any)
	if server["hostname"] != "persist.example.com" {
		t.Errorf("hostname not persisted: got %v", server["hostname"])
	}
}

func TestHandleSetServerSettings_ValidationRejectsEmptyHostname(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"hostname":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/server", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetServerSettings(w, req)

	// Empty hostname provided explicitly should be rejected.
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty hostname, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSetSmtpdSettings_ValidationRejectsInvalidLogLevel(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"log_level":"verbose"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/smtpd", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetSmtpdSettings(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid log_level, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSetSmtpdSettings_UpdatesLimits(t *testing.T) {
	h, cfgFile := newTestSettingsHandler(t)
	writeConfig(t, cfgFile, fullSharedConfig)

	body := `{"max_message_size":10485760,"max_recipients":50}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/smtpd", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetSmtpdSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(cfgFile)
	s := string(data)
	if !strings.Contains(s, "max_message_size = 10485760") {
		t.Errorf("expected updated max_message_size, got:\n%s", s)
	}
	if !strings.Contains(s, "max_recipients = 50") {
		t.Errorf("expected updated max_recipients, got:\n%s", s)
	}
}
