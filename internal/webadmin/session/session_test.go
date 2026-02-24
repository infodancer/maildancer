package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	store := NewStore(30 * time.Minute)

	rr := httptest.NewRecorder()
	sess, err := store.Create(rr, "admin")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if sess.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", sess.Username)
	}
	if sess.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if sess.CSRFToken == "" {
		t.Error("expected non-empty CSRF token")
	}

	// Verify cookie was set
	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == cookieName {
			found = true
			if !c.HttpOnly {
				t.Error("expected HttpOnly cookie")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Error("expected SameSite=Strict")
			}
		}
	}
	if !found {
		t.Error("session cookie not set")
	}

	// Get session back
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sess.ID})

	got := store.Get(req)
	if got == nil {
		t.Fatal("Get() returned nil")
	}
	if got.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", got.Username)
	}
}

func TestGetNoSession(t *testing.T) {
	store := NewStore(30 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := store.Get(req)
	if got != nil {
		t.Error("expected nil for request without cookie")
	}
}

func TestGetInvalidSession(t *testing.T) {
	store := NewStore(30 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "nonexistent"})

	got := store.Get(req)
	if got != nil {
		t.Error("expected nil for invalid session ID")
	}
}

func TestSessionExpiry(t *testing.T) {
	store := NewStore(1 * time.Millisecond)

	rr := httptest.NewRecorder()
	sess, err := store.Create(rr, "admin")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sess.ID})

	got := store.Get(req)
	if got != nil {
		t.Error("expected nil for expired session")
	}
}

func TestDestroy(t *testing.T) {
	store := NewStore(30 * time.Minute)

	rr := httptest.NewRecorder()
	sess, err := store.Create(rr, "admin")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Destroy session
	destroyRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sess.ID})
	store.Destroy(destroyRR, req)

	// Verify session is gone
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getReq.AddCookie(&http.Cookie{Name: cookieName, Value: sess.ID})
	got := store.Get(getReq)
	if got != nil {
		t.Error("expected nil after destroy")
	}

	// Verify cookie is cleared
	cookies := destroyRR.Result().Cookies()
	for _, c := range cookies {
		if c.Name == cookieName && c.MaxAge != -1 {
			t.Error("expected MaxAge=-1 to clear cookie")
		}
	}
}

func TestValidateCSRF(t *testing.T) {
	store := NewStore(30 * time.Minute)

	rr := httptest.NewRecorder()
	sess, err := store.Create(rr, "admin")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Valid CSRF via form
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Form = map[string][]string{
		csrfFormName: {sess.CSRFToken},
	}
	if !store.ValidateCSRF(req, sess) {
		t.Error("expected valid CSRF token")
	}

	// Valid CSRF via header
	req2 := httptest.NewRequest(http.MethodPost, "/action", nil)
	req2.Header.Set("X-CSRF-Token", sess.CSRFToken)
	if !store.ValidateCSRF(req2, sess) {
		t.Error("expected valid CSRF token via header")
	}

	// Invalid CSRF
	req3 := httptest.NewRequest(http.MethodPost, "/action", nil)
	req3.Form = map[string][]string{
		csrfFormName: {"wrong-token"},
	}
	if store.ValidateCSRF(req3, sess) {
		t.Error("expected invalid CSRF token")
	}

	// Missing CSRF
	req4 := httptest.NewRequest(http.MethodPost, "/action", nil)
	if store.ValidateCSRF(req4, sess) {
		t.Error("expected invalid for missing CSRF token")
	}
}
