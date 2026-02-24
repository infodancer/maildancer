// Package server implements the webadmin HTTP server.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/handlers"
	"github.com/infodancer/maildancer/internal/webadmin/middleware"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// Deps holds the external dependencies the server needs.
type Deps struct {
	AuthAgent auth.AuthenticationAgent
}

// Server is the webadmin HTTP server.
type Server struct {
	httpServer *http.Server
	mux        *http.ServeMux
	cfg        config.WebAdminConfig
	deps       Deps
	sessions   *session.Store
	logger     *slog.Logger
}

// New creates a new webadmin server with the given configuration.
func New(cfg config.WebAdminConfig, deps Deps, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	sessionTimeout := time.Duration(cfg.Session.TimeoutMinutes) * time.Minute
	if sessionTimeout == 0 {
		sessionTimeout = 30 * time.Minute
	}

	mux := http.NewServeMux()
	s := &Server{
		mux:      mux,
		cfg:      cfg,
		deps:     deps,
		sessions: session.NewStore(sessionTimeout),
		logger:   logger,
	}

	s.registerRoutes()

	// Wrap mux with global middleware
	s.httpServer = &http.Server{
		Addr: cfg.ListenAddress,
		Handler: middleware.Chain(mux,
			middleware.RequestLogger(logger),
			middleware.SecurityHeadersWithHSTS(cfg.TLSEnabled()),
		),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s
}

// registerRoutes sets up the HTTP route handlers.
func (s *Server) registerRoutes() {
	authHandler := handlers.NewAuthHandler(s.deps.AuthAgent, s.sessions, s.logger)
	domainHandler := handlers.NewDomainHandler(s.cfg.DomainsPath, s.sessions, s.logger)
	userHandler := handlers.NewUserHandler(s.cfg.DomainsPath, s.sessions, s.logger)
	statsHandler := handlers.NewStatsHandler(s.cfg.DomainsPath, s.sessions, s.logger, nil)
	webHandler := handlers.NewWebHandler(s.cfg.DomainsPath, s.sessions, s.logger)
	requireAuth := middleware.RequireAuth(s.sessions, s.logger)
	requireCSRF := middleware.RequireCSRF(s.sessions, s.logger)
	loginLimiter := middleware.NewRateLimiter(5, time.Minute)

	// Public routes
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /login", authHandler.HandleLoginPage)
	s.mux.Handle("POST /login", middleware.Chain(
		http.HandlerFunc(authHandler.HandleLogin),
		middleware.RateLimit(loginLimiter, s.logger),
	))

	// Authenticated routes
	s.mux.Handle("POST /logout", middleware.Chain(
		http.HandlerFunc(authHandler.HandleLogout),
		requireAuth, requireCSRF,
	))

	// Web UI pages (US-006)
	s.mux.Handle("GET /{$}", middleware.Chain(
		http.HandlerFunc(webHandler.HandleDashboard),
		requireAuth,
	))
	s.mux.Handle("GET /domains/{name}", middleware.Chain(
		http.HandlerFunc(webHandler.HandleDomainDetail),
		requireAuth,
	))

	// HTMX UI partials (US-006, US-007)
	s.mux.Handle("GET /ui/domains/new", middleware.Chain(
		http.HandlerFunc(webHandler.HandleNewDomainForm),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/confirm-delete", middleware.Chain(
		http.HandlerFunc(webHandler.HandleConfirmDeleteDomain),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/new", middleware.Chain(
		http.HandlerFunc(webHandler.HandleNewUserForm),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/confirm-delete", middleware.Chain(
		http.HandlerFunc(webHandler.HandleConfirmDeleteUser),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/reset-password", middleware.Chain(
		http.HandlerFunc(webHandler.HandleResetPasswordForm),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/generate-keys", middleware.Chain(
		http.HandlerFunc(webHandler.HandleGenerateKeysForm),
		requireAuth,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/stats", middleware.Chain(
		http.HandlerFunc(webHandler.HandleUserStats),
		requireAuth,
	))

	// Domain management API (US-003)
	s.mux.Handle("GET /api/domains", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleListDomains),
		requireAuth,
	))
	s.mux.Handle("GET /api/domains/{name}", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleGetDomain),
		requireAuth,
	))
	s.mux.Handle("POST /api/domains", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleCreateDomain),
		requireAuth, requireCSRF,
	))
	s.mux.Handle("DELETE /api/domains/{name}", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleDeleteDomain),
		requireAuth, requireCSRF,
	))

	// User management API (US-004)
	s.mux.Handle("GET /api/domains/{domain}/users", middleware.Chain(
		http.HandlerFunc(userHandler.HandleListUsers),
		requireAuth,
	))
	s.mux.Handle("POST /api/domains/{domain}/users", middleware.Chain(
		http.HandlerFunc(userHandler.HandleCreateUser),
		requireAuth, requireCSRF,
	))
	s.mux.Handle("DELETE /api/domains/{domain}/users/{username}", middleware.Chain(
		http.HandlerFunc(userHandler.HandleDeleteUser),
		requireAuth, requireCSRF,
	))
	s.mux.Handle("PUT /api/domains/{domain}/users/{username}/password", middleware.Chain(
		http.HandlerFunc(userHandler.HandleResetPassword),
		requireAuth, requireCSRF,
	))

	// Key management API (US-004)
	s.mux.Handle("GET /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleGetKeys),
		requireAuth,
	))
	s.mux.Handle("POST /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleCreateKeys),
		requireAuth, requireCSRF,
	))
	s.mux.Handle("DELETE /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleDeleteKeys),
		requireAuth, requireCSRF,
	))

	// Mailbox statistics API (US-005)
	s.mux.Handle("GET /api/domains/{domain}/users/{username}/stats", middleware.Chain(
		http.HandlerFunc(statsHandler.HandleGetStats),
		requireAuth,
	))
}

// handleHealth responds with a 200 OK status for health checks.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		s.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.logger.Info("webadmin server starting",
		slog.String("address", ln.Addr().String()),
		slog.Bool("tls", s.cfg.TLSEnabled()))

	errCh := make(chan error, 1)
	go func() {
		if s.cfg.TLSEnabled() {
			errCh <- s.httpServer.ServeTLS(ln, "", "")
		} else {
			errCh <- s.httpServer.Serve(ln)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down webadmin server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server: %w", err)
		}
		return nil
	}
}
