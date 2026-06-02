// Package server implements the webadmin HTTP server.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/handlers"
	"github.com/infodancer/maildancer/internal/webadmin/metrics"
	"github.com/infodancer/maildancer/internal/webadmin/middleware"
	"github.com/infodancer/maildancer/internal/webadmin/promclient"
	"github.com/infodancer/maildancer/internal/webadmin/rbac"
	"github.com/infodancer/maildancer/internal/webadmin/session"
	"github.com/pelletier/go-toml/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Deps holds the external dependencies the server needs.
type Deps struct {
	AuthAgent auth.AuthenticationAgent
}

// Server is the webadmin HTTP server.
type Server struct {
	httpServer    *http.Server
	mux           *http.ServeMux
	cfg           config.WebAdminConfig
	deps          Deps
	sessions      *session.Store
	logger        *slog.Logger
	roles         atomic.Pointer[rbac.RoleStore] // read atomically; written only under rolesMu
	rolesMu       sync.Mutex                     // serializes updateRolesFile
	auditLog      *audit.Logger
	rolesFilePath string
}

// New creates a new webadmin server with the given configuration.
func New(cfg config.WebAdminConfig, deps Deps, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	sessionTimeout := time.Duration(cfg.Session.TimeoutMinutes) * time.Minute
	if sessionTimeout == 0 {
		sessionTimeout = 30 * time.Minute
	}

	// Load RBAC roles
	roles, err := rbac.LoadRoles(cfg.Auth.RolesFile)
	if err != nil {
		return nil, fmt.Errorf("load roles: %w", err)
	}
	if cfg.Auth.RolesFile != "" {
		logger.Info("RBAC roles loaded", slog.String("file", cfg.Auth.RolesFile), slog.Int("admins", len(roles.Admins)))
	}

	// Create audit logger
	auditLog, err := audit.NewLogger(cfg.Audit.LogFile, logger)
	if err != nil {
		return nil, fmt.Errorf("create audit logger: %w", err)
	}
	if cfg.Audit.LogFile != "" {
		logger.Info("audit logging enabled", slog.String("file", cfg.Audit.LogFile))
	}

	// Register Prometheus metrics
	if err := metrics.Register(prometheus.DefaultRegisterer); err != nil {
		logger.Warn("failed to register metrics (already registered?)", slog.String("error", err.Error()))
	}

	if cfg.Auth.RolesFile == "" {
		logger.Warn("RBAC disabled: roles_file not configured — all authenticated users have super_admin access")
	}

	mux := http.NewServeMux()
	s := &Server{
		mux:           mux,
		cfg:           cfg,
		deps:          deps,
		sessions:      session.NewStore(sessionTimeout, cfg.TLSEnabled()),
		logger:        logger,
		auditLog:      auditLog,
		rolesFilePath: cfg.Auth.RolesFile,
	}
	s.roles.Store(roles)

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

	return s, nil
}

// registerRoutes sets up the HTTP route handlers.
func (s *Server) registerRoutes() {
	// Snapshot current roles for handler constructors (secondary defence-in-depth checks).
	currentRoles := s.roles.Load()
	authHandler := handlers.NewAuthHandler(s.deps.AuthAgent, s.sessions, s.logger)
	domainHandler := handlers.NewDomainHandler(s.cfg.DomainsPath, s.cfg.EffectiveDataPath(), s.sessions, s.logger, currentRoles, s.auditLog)
	userHandler := handlers.NewUserHandler(s.cfg.DomainsPath, s.cfg.EffectiveDataPath(), s.sessions, s.logger, s.auditLog)
	statsHandler := handlers.NewStatsHandler(s.cfg.DomainsPath, s.sessions, s.logger, nil)
	mailStatsHandler := handlers.NewMailStatsHandler(promclient.New(s.cfg.Prometheus.URLs), s.sessions, s.logger)
	webHandler := handlers.NewWebHandler(s.cfg.DomainsPath, s.sessions, s.logger, currentRoles)
	dashboardHandler := handlers.NewDashboardHandler(s.cfg.DomainsPath, s.sessions, s.logger)
	rspamdHandler := handlers.NewRspamdHandler(s.cfg.FilePath, s.sessions, s.logger)
	settingsHandler := handlers.NewSettingsHandler(s.cfg.FilePath, s.sessions, s.logger)
	outboundHandler := handlers.NewOutboundHandler(s.cfg.DomainsPath, s.sessions, s.logger, s.auditLog)
	dnsHandler := handlers.NewDNSHandler(s.cfg.DomainsPath, s.sessions, s.logger, settingsHandler)
	webHandler.SetConfigFile(s.cfg.FilePath)
	webHandler.SetSettingsHandler(settingsHandler)
	webHandler.SetOutboundHandler(outboundHandler)

	requireAuth := middleware.RequireAuth(s.sessions, s.logger)
	requireCSRF := middleware.RequireCSRF(s.sessions, s.logger)
	// getRoles is called on every request so role updates take effect immediately in middleware.
	getRoles := func() *rbac.RoleStore { return s.roles.Load() }
	requireSuperAdmin := middleware.RequireSuperAdmin(s.sessions, getRoles)
	requireDomainAccessByName := middleware.RequireDomainAccess(s.sessions, getRoles, "name")
	requireDomainAccessByDomain := middleware.RequireDomainAccess(s.sessions, getRoles, "domain")

	loginLimiter := middleware.NewRateLimiter(5, time.Minute)

	// Public routes
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.Handle("GET /login", http.HandlerFunc(authHandler.HandleLoginPage))
	s.mux.Handle("POST /login", middleware.Chain(
		http.HandlerFunc(authHandler.HandleLogin),
		middleware.RateLimit(loginLimiter, s.logger),
	))

	// Prometheus metrics — requires authentication.
	// Configure Prometheus with basic_auth if scraping this endpoint externally.
	s.mux.Handle("GET /metrics", middleware.Chain(
		promhttp.Handler(),
		requireAuth,
	))

	// Authenticated routes
	s.mux.Handle("POST /logout", middleware.Chain(
		http.HandlerFunc(authHandler.HandleLogout),
		requireAuth, requireCSRF,
	))

	// Web UI pages
	s.mux.Handle("GET /{$}", middleware.Chain(
		http.HandlerFunc(webHandler.HandleDashboard),
		requireAuth,
	))
	s.mux.Handle("GET /domains/{name}", middleware.Chain(
		http.HandlerFunc(webHandler.HandleDomainDetail),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /domains/{name}/dns", middleware.Chain(
		http.HandlerFunc(webHandler.HandleDNSWizard),
		requireAuth, requireDomainAccessByName,
	))

	// DNS check API
	s.mux.Handle("GET /api/domains/{name}/dns/check", middleware.Chain(
		http.HandlerFunc(dnsHandler.HandleCheckDNSRecord),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /api/domains/{name}/dns/status", middleware.Chain(
		http.HandlerFunc(dnsHandler.HandleDNSStatus),
		requireAuth, requireDomainAccessByName,
	))

	// HTMX UI partials
	s.mux.Handle("GET /ui/domains/new", middleware.Chain(
		http.HandlerFunc(webHandler.HandleNewDomainForm),
		requireAuth, requireSuperAdmin,
	))
	s.mux.Handle("GET /ui/domains/{name}/confirm-delete", middleware.Chain(
		http.HandlerFunc(webHandler.HandleConfirmDeleteDomain),
		requireAuth, requireSuperAdmin,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/new", middleware.Chain(
		http.HandlerFunc(webHandler.HandleNewUserForm),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/confirm-delete", middleware.Chain(
		http.HandlerFunc(webHandler.HandleConfirmDeleteUser),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/reset-password", middleware.Chain(
		http.HandlerFunc(webHandler.HandleResetPasswordForm),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/generate-keys", middleware.Chain(
		http.HandlerFunc(webHandler.HandleGenerateKeysForm),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /ui/domains/{name}/users/{username}/stats", middleware.Chain(
		http.HandlerFunc(webHandler.HandleUserStats),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("GET /ui/domains/{name}/generate-keys", middleware.Chain(
		http.HandlerFunc(webHandler.HandleGenerateDomainKeysForm),
		requireAuth, requireDomainAccessByName,
	))

	// Dashboard stats API
	s.mux.Handle("GET /api/dashboard", middleware.Chain(
		http.HandlerFunc(dashboardHandler.HandleGetDashboard),
		requireAuth,
	))

	// Mail server stats API (queries Prometheus)
	s.mux.Handle("GET /api/mailstats", middleware.Chain(
		http.HandlerFunc(mailStatsHandler.HandleGetMailStats),
		requireAuth,
	))

	// Domain management API
	s.mux.Handle("GET /api/domains", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleListDomains),
		requireAuth,
	))
	s.mux.Handle("GET /api/domains/{name}", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleGetDomain),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("POST /api/domains", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleCreateDomain),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("DELETE /api/domains/{name}", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleDeleteDomain),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("PUT /api/domains/{name}/config", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleUpdateDomainConfig),
		requireAuth, requireCSRF, requireDomainAccessByName,
	))

	// Domain key management API
	s.mux.Handle("GET /api/domains/{name}/keys", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleGetDomainKeys),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("POST /api/domains/{name}/keys", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleCreateDomainKeys),
		requireAuth, requireCSRF, requireDomainAccessByName,
	))
	s.mux.Handle("DELETE /api/domains/{name}/keys", middleware.Chain(
		http.HandlerFunc(domainHandler.HandleDeleteDomainKeys),
		requireAuth, requireCSRF, requireDomainAccessByName,
	))

	// User management API
	s.mux.Handle("GET /api/domains/{domain}/users", middleware.Chain(
		http.HandlerFunc(userHandler.HandleListUsers),
		requireAuth, requireDomainAccessByDomain,
	))
	s.mux.Handle("POST /api/domains/{domain}/users", middleware.Chain(
		http.HandlerFunc(userHandler.HandleCreateUser),
		requireAuth, requireCSRF, requireDomainAccessByDomain,
	))
	s.mux.Handle("DELETE /api/domains/{domain}/users/{username}", middleware.Chain(
		http.HandlerFunc(userHandler.HandleDeleteUser),
		requireAuth, requireCSRF, requireDomainAccessByDomain,
	))
	s.mux.Handle("PUT /api/domains/{domain}/users/{username}/password", middleware.Chain(
		http.HandlerFunc(userHandler.HandleResetPassword),
		requireAuth, requireCSRF, requireDomainAccessByDomain,
	))

	// User key management API
	s.mux.Handle("GET /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleGetKeys),
		requireAuth, requireDomainAccessByDomain,
	))
	s.mux.Handle("POST /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleCreateKeys),
		requireAuth, requireCSRF, requireDomainAccessByDomain,
	))
	s.mux.Handle("DELETE /api/domains/{domain}/users/{username}/keys", middleware.Chain(
		http.HandlerFunc(userHandler.HandleDeleteKeys),
		requireAuth, requireCSRF, requireDomainAccessByDomain,
	))

	// Mailbox statistics API
	s.mux.Handle("GET /api/domains/{domain}/users/{username}/stats", middleware.Chain(
		http.HandlerFunc(statsHandler.HandleGetStats),
		requireAuth, requireDomainAccessByDomain,
	))

	// Rspamd settings API
	s.mux.Handle("GET /api/rspamd", middleware.Chain(
		http.HandlerFunc(rspamdHandler.HandleGetRspamd),
		requireAuth,
	))
	s.mux.Handle("POST /api/rspamd", middleware.Chain(
		http.HandlerFunc(rspamdHandler.HandleSetRspamd),
		requireAuth, requireCSRF, requireSuperAdmin,
	))

	// Settings API (super_admin only for writes)
	s.mux.Handle("GET /api/settings", middleware.Chain(
		http.HandlerFunc(settingsHandler.HandleGetSettings),
		requireAuth,
	))
	s.mux.Handle("POST /api/settings/server", middleware.Chain(
		http.HandlerFunc(settingsHandler.HandleSetServerSettings),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("POST /api/settings/smtpd", middleware.Chain(
		http.HandlerFunc(settingsHandler.HandleSetSmtpdSettings),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("POST /api/settings/pop3d", middleware.Chain(
		http.HandlerFunc(settingsHandler.HandleSetPop3dSettings),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("POST /api/settings/spamcheck", middleware.Chain(
		http.HandlerFunc(settingsHandler.HandleSetSpamcheckSettings),
		requireAuth, requireCSRF, requireSuperAdmin,
	))

	// Outbound transport routing API
	s.mux.Handle("GET /api/domains/{name}/outbound", middleware.Chain(
		http.HandlerFunc(outboundHandler.HandleGetDomainOutbound),
		requireAuth, requireDomainAccessByName,
	))
	s.mux.Handle("PUT /api/domains/{name}/outbound", middleware.Chain(
		http.HandlerFunc(outboundHandler.HandleSetDomainOutbound),
		requireAuth, requireCSRF, requireDomainAccessByName,
	))
	s.mux.Handle("GET /api/outbound/default", middleware.Chain(
		http.HandlerFunc(outboundHandler.HandleGetDefaultOutbound),
		requireAuth, requireSuperAdmin,
	))
	s.mux.Handle("PUT /api/outbound/default", middleware.Chain(
		http.HandlerFunc(outboundHandler.HandleSetDefaultOutbound),
		requireAuth, requireCSRF, requireSuperAdmin,
	))

	// Migration API (super_admin only — idempotent, safe to re-run)
	migrateHandler := handlers.NewMigrateHandler(s.cfg.DomainsPath, s.cfg.EffectiveDataPath(), s.sessions, s.logger, s.auditLog)
	s.mux.Handle("POST /api/migrate/uids", middleware.Chain(
		http.HandlerFunc(migrateHandler.HandleMigrateUIDs),
		requireAuth, requireCSRF, requireSuperAdmin,
	))

	// Settings UI page
	s.mux.Handle("GET /settings", middleware.Chain(
		http.HandlerFunc(webHandler.HandleSettings),
		requireAuth,
	))

	// Audit log API (super_admin only)
	s.mux.Handle("GET /api/audit", middleware.Chain(
		http.HandlerFunc(s.handleGetAuditLog),
		requireAuth, requireSuperAdmin,
	))

	// RBAC roles API (super_admin only)
	s.mux.Handle("GET /api/roles", middleware.Chain(
		http.HandlerFunc(s.handleGetRoles),
		requireAuth, requireSuperAdmin,
	))
	s.mux.Handle("POST /api/roles/{username}", middleware.Chain(
		http.HandlerFunc(s.handleSetRole),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
	s.mux.Handle("DELETE /api/roles/{username}", middleware.Chain(
		http.HandlerFunc(s.handleDeleteRole),
		requireAuth, requireCSRF, requireSuperAdmin,
	))
}

// handleHealth responds with a 200 OK status for health checks.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handleGetAuditLog returns the most recent audit log entries (super_admin only).
func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.auditLog.ReadRecent(100)
	if err != nil {
		s.logger.Error("failed to read audit log", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read audit log"})
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleGetRoles returns the current RBAC role assignments (super_admin only).
func (s *Server) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	roles := s.roles.Load()
	if roles == nil {
		writeJSON(w, http.StatusOK, map[string]any{"admins": map[string]any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": roles.Admins})
}

// handleSetRole assigns a role and domains to an admin (super_admin only).
func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	if s.rolesFilePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "roles_file not configured"})
		return
	}

	username := r.PathValue("username")
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
		return
	}

	var req struct {
		Role    rbac.Role `json:"role"`
		Domains []string  `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Role != rbac.RoleSuperAdmin && req.Role != rbac.RoleDomainAdmin {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be super_admin or domain_admin"})
		return
	}

	if err := s.updateRolesFile(func(store *rbac.RoleStore) {
		store.Admins[username] = rbac.AdminEntry{Role: req.Role, Domains: req.Domains}
	}); err != nil {
		s.logger.Error("failed to update roles file", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save roles"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(r.Context(), audit.Entry{
			Operation: "set_role",
			Target:    username,
			Result:    "success",
			Detail:    string(req.Role),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "role_set"})
}

// handleDeleteRole removes an admin's role assignment (super_admin only).
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if s.rolesFilePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "roles_file not configured"})
		return
	}

	username := r.PathValue("username")
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
		return
	}

	if err := s.updateRolesFile(func(store *rbac.RoleStore) {
		delete(store.Admins, username)
	}); err != nil {
		s.logger.Error("failed to update roles file", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save roles"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(r.Context(), audit.Entry{
			Operation: "delete_role",
			Target:    username,
			Result:    "success",
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "role_deleted"})
}

// updateRolesFile applies a mutation to the role store and persists it atomically.
// The full load→mutate→write→reload sequence is serialized under rolesMu.
func (s *Server) updateRolesFile(mutate func(*rbac.RoleStore)) error {
	s.rolesMu.Lock()
	defer s.rolesMu.Unlock()

	store, err := rbac.LoadRoles(s.rolesFilePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("load roles: %w", err)
	}
	if store == nil {
		store = &rbac.RoleStore{Admins: make(map[string]rbac.AdminEntry)}
	}

	mutate(store)

	data, err := toml.Marshal(store)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}

	// Write to a temp file then rename for crash-safe atomic update.
	dir := filepath.Dir(s.rolesFilePath)
	tmp, err := os.CreateTemp(dir, ".roles-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("create temp roles file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp roles file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp roles file: %w", err)
	}
	if err := os.Rename(tmpName, s.rolesFilePath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename roles file: %w", err)
	}

	// Reload and publish atomically.
	reloaded, err := rbac.LoadRoles(s.rolesFilePath)
	if err != nil {
		return fmt.Errorf("reload roles: %w", err)
	}
	s.roles.Store(reloaded)
	return nil
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
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
