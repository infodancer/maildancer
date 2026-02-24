package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/webadmin/config"
)

// mockAuthAgent is a test double for auth.AuthenticationAgent.
type mockAuthAgent struct{}

func (m *mockAuthAgent) Authenticate(_ context.Context, _, _ string) (*auth.AuthSession, error) {
	return nil, autherrors.ErrAuthFailed
}
func (m *mockAuthAgent) UserExists(_ context.Context, _ string) (bool, error) { return false, nil }
func (m *mockAuthAgent) Close() error                                         { return nil }

func testServer() *Server {
	cfg := config.WebAdminConfig{
		ListenAddress: "localhost:0",
		Session:       config.SessionConfig{TimeoutMinutes: 30},
	}
	deps := Deps{AuthAgent: &mockAuthAgent{}}
	return New(cfg, deps, slog.Default())
}

func TestServerStartStop(t *testing.T) {
	srv := testServer()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
}

func TestHealthHandler(t *testing.T) {
	srv := testServer()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rr.Body.String())
	}
}

func TestLoginPageRendered(t *testing.T) {
	srv := testServer()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestDashboardRequiresAuth(t *testing.T) {
	srv := testServer()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}
