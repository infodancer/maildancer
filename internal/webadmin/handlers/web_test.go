package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestWebHandler(t *testing.T) (*WebHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30 * time.Minute, false)
	return NewWebHandler(dir, store, slog.Default(), nil), dir
}

func TestHandleDashboard_EmptyDomains(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.HandleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Domains") {
		t.Error("expected 'Domains' heading in dashboard")
	}
	if !strings.Contains(body, "0 domains configured") {
		t.Error("expected '0 domains configured' in dashboard")
	}
}

func TestHandleDashboard_WithDomains(t *testing.T) {
	h, dir := newTestWebHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.HandleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "example.com") {
		t.Error("expected 'example.com' in dashboard")
	}
	if !strings.Contains(body, "1 domain configured") {
		t.Errorf("expected '1 domain configured' in dashboard, got: %s", body)
	}
}

func TestHandleDomainDetail(t *testing.T) {
	h, dir := newTestWebHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/domains/example.com", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleDomainDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "example.com") {
		t.Error("expected domain name in detail page")
	}
	if !strings.Contains(body, "user1") {
		t.Error("expected user1 in detail page")
	}
}

func TestHandleDomainDetail_NotFound(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/domains/missing.com", nil)
	req.SetPathValue("name", "missing.com")
	rr := httptest.NewRecorder()
	h.HandleDomainDetail(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleDomainDetail_InvalidName(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/domains/../etc", nil)
	req.SetPathValue("name", "../etc")
	rr := httptest.NewRecorder()
	h.HandleDomainDetail(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleNewDomainForm(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/ui/domains/new", nil)
	rr := httptest.NewRecorder()
	h.HandleNewDomainForm(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Create Domain") {
		t.Error("expected create domain form")
	}
}

func TestHandleConfirmDeleteDomain(t *testing.T) {
	h, dir := newTestWebHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/ui/domains/example.com/confirm-delete", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleConfirmDeleteDomain(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Delete example.com?") {
		t.Error("expected delete confirmation text")
	}
}

func TestHandleNewUserForm(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/ui/domains/example.com/users/new", nil)
	req.SetPathValue("name", "example.com")
	rr := httptest.NewRecorder()
	h.HandleNewUserForm(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Create User") {
		t.Error("expected create user form")
	}
}

func TestHandleResetPasswordForm(t *testing.T) {
	h, _ := newTestWebHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/ui/domains/example.com/users/alice/reset-password", nil)
	req.SetPathValue("name", "example.com")
	req.SetPathValue("username", "alice")
	rr := httptest.NewRecorder()
	h.HandleResetPasswordForm(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alice") {
		t.Error("expected username in reset password form")
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1536000, "1.5 MB"},
	}
	for _, tt := range tests {
		got := humanBytes(tt.bytes)
		if got != tt.expected {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.bytes, got, tt.expected)
		}
	}
}
