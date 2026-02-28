package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func TestRequireAuth_Unauthenticated(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()

	handler := RequireAuth(store, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestRequireAuth_Authenticated(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()

	// Create session
	createRR := httptest.NewRecorder()
	sess, err := store.Create(createRR, "admin")
	if err != nil {
		t.Fatal(err)
	}

	var called bool
	handler := RequireAuth(store, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called for authenticated request")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireCSRF_GetPassesThrough(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()

	var called bool
	handler := RequireCSRF(store, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected GET to pass through CSRF check")
	}
}

func TestRequireCSRF_PostWithoutToken(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()

	createRR := httptest.NewRecorder()
	sess, _ := store.Create(createRR, "admin")

	handler := RequireCSRF(store, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRequireCSRF_PostWithValidToken(t *testing.T) {
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()

	createRR := httptest.NewRecorder()
	sess, _ := store.Create(createRR, "admin")

	var called bool
	handler := RequireCSRF(store, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	req.Form = map[string][]string{
		"csrf_token": {sess.CSRFToken},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called with valid CSRF token")
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for header, want := range expected {
		got := rr.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	handler := SecurityHeadersWithHSTS(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	hsts := rr.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected Strict-Transport-Security header when TLS enabled")
	}
}

func TestSecurityHeaders_NoHSTSWithoutTLS(t *testing.T) {
	handler := SecurityHeadersWithHSTS(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	hsts := rr.Header().Get("Strict-Transport-Security")
	if hsts != "" {
		t.Error("expected no HSTS header without TLS")
	}
}

func TestChain(t *testing.T) {
	var order []int

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, 1)
			next.ServeHTTP(w, r)
		})
	}
	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, 2)
			next.ServeHTTP(w, r)
		})
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, 3)
	}), m1, m2)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Errorf("expected middleware order [1,2,3], got %v", order)
	}
}
