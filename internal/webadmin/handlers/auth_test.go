package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// mockAuthAgent is a test double for auth.AuthenticationAgent.
type mockAuthAgent struct {
	users map[string]string // username -> password
}

func (m *mockAuthAgent) Authenticate(_ context.Context, username, password string) (*auth.AuthSession, error) {
	if p, ok := m.users[username]; ok && p == password {
		return &auth.AuthSession{
			User: &auth.User{
				Username: username,
				Mailbox:  username,
			},
		}, nil
	}
	return nil, autherrors.ErrAuthFailed
}

func (m *mockAuthAgent) UserExists(_ context.Context, username string) (bool, error) {
	_, ok := m.users[username]
	return ok, nil
}

func (m *mockAuthAgent) Close() error { return nil }

func newTestAuthHandler() (*AuthHandler, *session.Store) {
	agent := &mockAuthAgent{
		users: map[string]string{"admin": "secret123"},
	}
	store := session.NewStore(30 * time.Minute, false)
	logger := slog.Default()
	return NewAuthHandler(agent, store, logger), store
}

func TestHandleLoginPage(t *testing.T) {
	h, _ := newTestAuthHandler()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Mail Admin") {
		t.Error("expected login page content")
	}
	if !strings.Contains(body, `action="/login"`) {
		t.Error("expected login form action")
	}
}

func TestHandleLoginPage_AlreadyLoggedIn(t *testing.T) {
	h, store := newTestAuthHandler()

	// Create a session
	createRR := httptest.NewRecorder()
	sess, _ := store.Create(createRR, "admin")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/" {
		t.Errorf("expected redirect to /, got %q", loc)
	}
}

func TestHandleLogin_Success(t *testing.T) {
	h, _ := newTestAuthHandler()

	form := url.Values{
		"username": {"admin"},
		"password": {"secret123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleLogin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/" {
		t.Errorf("expected redirect to /, got %q", loc)
	}

	// Verify session cookie was set
	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "webadmin_session" {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie")
	}
}

func TestHandleLogin_InvalidCredentials(t *testing.T) {
	h, _ := newTestAuthHandler()

	form := url.Values{
		"username": {"admin"},
		"password": {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (login page with error), got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid username or password") {
		t.Error("expected error message in response")
	}
}

func TestHandleLogin_EmptyFields(t *testing.T) {
	h, _ := newTestAuthHandler()

	form := url.Values{
		"username": {""},
		"password": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleLogin(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "required") {
		t.Error("expected 'required' error message")
	}
}

func TestHandleLogout(t *testing.T) {
	h, store := newTestAuthHandler()

	createRR := httptest.NewRecorder()
	sess, _ := store.Create(createRR, "admin")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}

	// Verify session is destroyed
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getReq.AddCookie(&http.Cookie{Name: "webadmin_session", Value: sess.ID})
	if got := store.Get(getReq); got != nil {
		t.Error("expected session to be destroyed")
	}
}
