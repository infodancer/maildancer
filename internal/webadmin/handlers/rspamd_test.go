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

func newTestRspamdHandler(t *testing.T) (*RspamdHandler, string) {
	t.Helper()
	dir := t.TempDir()
	rspamdFile := filepath.Join(dir, "rspamd.toml")
	store := session.NewStore(30*time.Minute, false)
	return NewRspamdHandler(rspamdFile, store, slog.Default()), rspamdFile
}

func TestHandleGetRspamd_NoFile(t *testing.T) {
	h, rspamdFile := newTestRspamdHandler(t)
	// File doesn't exist yet
	_ = os.Remove(rspamdFile)

	req := httptest.NewRequest(http.MethodGet, "/api/rspamd", nil)
	w := httptest.NewRecorder()
	h.HandleGetRspamd(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["url"] != "" {
		t.Errorf("url: want empty, got %q", resp["url"])
	}
	if resp["has_password"] != false {
		t.Errorf("has_password: want false, got %v", resp["has_password"])
	}
	if _, ok := resp["password"]; ok {
		t.Error("password field must not appear in response")
	}
}

func TestHandleSetRspamd_And_Get(t *testing.T) {
	h, _ := newTestRspamdHandler(t)

	body := `{"url":"http://rspamd.local:11334","password":"secret"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rspamd", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetRspamd(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Read back
	req2 := httptest.NewRequest(http.MethodGet, "/api/rspamd", nil)
	w2 := httptest.NewRecorder()
	h.HandleGetRspamd(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("GET: want 200, got %d", w2.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["url"] != "http://rspamd.local:11334" {
		t.Errorf("url: want %q, got %q", "http://rspamd.local:11334", resp["url"])
	}
	if resp["has_password"] != true {
		t.Errorf("has_password: want true, got %v", resp["has_password"])
	}
	if _, ok := resp["password"]; ok {
		t.Error("password must not appear in GET response")
	}
}

func TestHandleSetRspamd_URLOnly(t *testing.T) {
	h, _ := newTestRspamdHandler(t)

	body := `{"url":"http://localhost:11334"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rspamd", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSetRspamd(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/rspamd", nil)
	w2 := httptest.NewRecorder()
	h.HandleGetRspamd(w2, req2)

	var resp map[string]any
	_ = json.NewDecoder(w2.Body).Decode(&resp)
	if resp["url"] != "http://localhost:11334" {
		t.Errorf("url: want %q, got %q", "http://localhost:11334", resp["url"])
	}
	if resp["has_password"] != false {
		t.Errorf("has_password: want false, got %v", resp["has_password"])
	}
}

func TestHandleSetRspamd_PreservesExistingPassword(t *testing.T) {
	h, _ := newTestRspamdHandler(t)

	// Set URL + password
	req := httptest.NewRequest(http.MethodPost, "/api/rspamd",
		strings.NewReader(`{"url":"http://localhost:11334","password":"existing"}`))
	h.HandleSetRspamd(httptest.NewRecorder(), req)

	// Update URL only — password should be preserved
	req2 := httptest.NewRequest(http.MethodPost, "/api/rspamd",
		strings.NewReader(`{"url":"http://newhost:11334"}`))
	w2 := httptest.NewRecorder()
	h.HandleSetRspamd(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w2.Code)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/api/rspamd", nil)
	w3 := httptest.NewRecorder()
	h.HandleGetRspamd(w3, req3)

	var resp map[string]any
	_ = json.NewDecoder(w3.Body).Decode(&resp)
	if resp["url"] != "http://newhost:11334" {
		t.Errorf("url not updated: got %q", resp["url"])
	}
	if resp["has_password"] != true {
		t.Error("existing password should have been preserved")
	}
}

func TestHandleSetRspamd_NoFileConfigured(t *testing.T) {
	store := session.NewStore(30*time.Minute, false)
	h := NewRspamdHandler("", store, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/api/rspamd",
		strings.NewReader(`{"url":"http://localhost:11334"}`))
	w := httptest.NewRecorder()
	h.HandleSetRspamd(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when no file configured, got %d", w.Code)
	}
}

func TestHandleSetRspamd_InvalidJSON(t *testing.T) {
	h, _ := newTestRspamdHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/rspamd",
		strings.NewReader("not json"))
	w := httptest.NewRecorder()
	h.HandleSetRspamd(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleSetRspamd_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	rspamdFile := filepath.Join(dir, "rspamd.toml")
	store := session.NewStore(30*time.Minute, false)

	h1 := NewRspamdHandler(rspamdFile, store, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/api/rspamd",
		strings.NewReader(`{"url":"http://rspamd:11334","password":"pw"}`))
	h1.HandleSetRspamd(httptest.NewRecorder(), req)

	// New handler instance reads the same file
	h2 := NewRspamdHandler(rspamdFile, store, slog.Default())
	req2 := httptest.NewRequest(http.MethodGet, "/api/rspamd", nil)
	w2 := httptest.NewRecorder()
	h2.HandleGetRspamd(w2, req2)

	var resp map[string]any
	_ = json.NewDecoder(w2.Body).Decode(&resp)
	if resp["url"] != "http://rspamd:11334" {
		t.Errorf("url not persisted: got %q", resp["url"])
	}
	if resp["has_password"] != true {
		t.Error("password not persisted")
	}
}
