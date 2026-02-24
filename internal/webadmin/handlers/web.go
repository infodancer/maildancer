package handlers

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// uiDomainRow holds domain data for dashboard rendering.
type uiDomainRow struct {
	Name      string
	UserCount int
	AuthType  string
	StoreType string
}

// uiUserRow holds user data for domain detail rendering.
type uiUserRow struct {
	Username          string
	EncryptionEnabled bool
}

// WebHandler serves the HTML UI pages and HTMX partials.
type WebHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
	render      *Renderer
}

// NewWebHandler creates a new web UI handler.
func NewWebHandler(domainsPath string, sessions *session.Store, logger *slog.Logger) *WebHandler {
	return &WebHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
		render:      NewRenderer(),
	}
}

// pageData builds common PageData from the request session.
func (h *WebHandler) pageData(r *http.Request, data any) PageData {
	pd := PageData{Data: data}
	if sess := h.sessions.Get(r); sess != nil {
		pd.Username = sess.Username
		pd.CSRFToken = sess.CSRFToken
	}
	return pd
}

// HandleDashboard renders the main dashboard with domain list.
func (h *WebHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(h.domainsPath)
	if err != nil && !os.IsNotExist(err) {
		h.logger.Error("failed to read domains directory", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var domains []uiDomainRow
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainPath := filepath.Join(h.domainsPath, entry.Name())
		configPath := filepath.Join(domainPath, "config.toml")
		if _, err := os.Stat(configPath); err != nil {
			continue
		}

		data, _ := os.ReadFile(configPath)
		authType := extractTOMLValue(string(data), "type", "auth")
		storeType := extractTOMLValue(string(data), "type", "msgstore")
		userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

		domains = append(domains, uiDomainRow{
			Name:      entry.Name(),
			UserCount: userCount,
			AuthType:  authType,
			StoreType: storeType,
		})
	}

	if domains == nil {
		domains = []uiDomainRow{}
	}

	pd := h.pageData(r, nil)
	pd.Data = struct{ Domains []uiDomainRow }{Domains: domains}
	if err := h.render.Render(w, "dashboard", pd); err != nil {
		h.logger.Error("failed to render dashboard", "error", err)
	}
}

// HandleDomainDetail renders the domain detail page with user list.
func (h *WebHandler) HandleDomainDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		http.Error(w, "Invalid domain name", http.StatusBadRequest)
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Read domain config
	configData, _ := os.ReadFile(filepath.Join(domainPath, "config.toml"))
	authType := extractTOMLValue(string(configData), "type", "auth")
	storeType := extractTOMLValue(string(configData), "type", "msgstore")
	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

	users := h.listUsersForUI(domainPath)

	pd := h.pageData(r, nil)
	pd.Data = struct {
		Domain uiDomainRow
		Users  []uiUserRow
	}{
		Domain: uiDomainRow{
			Name:      name,
			UserCount: userCount,
			AuthType:  authType,
			StoreType: storeType,
		},
		Users: users,
	}

	if err := h.render.Render(w, "domain", pd); err != nil {
		h.logger.Error("failed to render domain page", "error", err)
	}
}

// listUsersForUI reads the passwd file and checks key status for each user.
func (h *WebHandler) listUsersForUI(domainPath string) []uiUserRow {
	passwdPath := filepath.Join(domainPath, "passwd")
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return nil
	}

	keysDir := filepath.Join(domainPath, "keys")
	var users []uiUserRow

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		username := strings.TrimSpace(parts[0])
		if username == "" {
			continue
		}

		hasKeys := false
		pubKeyPath := filepath.Join(keysDir, username+".pub")
		if _, err := os.Stat(pubKeyPath); err == nil {
			hasKeys = true
		}

		users = append(users, uiUserRow{
			Username:          username,
			EncryptionEnabled: hasKeys,
		})
	}
	return users
}

// HandleNewDomainForm returns the HTMX partial for the create domain form.
func (h *WebHandler) HandleNewDomainForm(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "create-domain-form", struct{ CSRFToken string }{csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleConfirmDeleteDomain returns the HTMX partial for domain delete confirmation.
func (h *WebHandler) HandleConfirmDeleteDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		http.Error(w, "Invalid domain name", http.StatusBadRequest)
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "confirm-delete-domain", struct {
		Name      string
		UserCount int
		CSRFToken string
	}{name, userCount, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleNewUserForm returns the HTMX partial for the create user form.
func (h *WebHandler) HandleNewUserForm(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "create-user-form", struct {
		Domain    string
		CSRFToken string
	}{domain, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleConfirmDeleteUser returns the HTMX partial for user delete confirmation.
func (h *WebHandler) HandleConfirmDeleteUser(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	username := r.PathValue("username")
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "confirm-delete-user", struct {
		Domain    string
		Username  string
		CSRFToken string
	}{domain, username, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleResetPasswordForm returns the HTMX partial for the password reset form.
func (h *WebHandler) HandleResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	username := r.PathValue("username")
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "reset-password-form", struct {
		Domain    string
		Username  string
		CSRFToken string
	}{domain, username, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleGenerateKeysForm returns the HTMX partial for the key generation form.
func (h *WebHandler) HandleGenerateKeysForm(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	username := r.PathValue("username")
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "generate-keys-form", struct {
		Domain    string
		Username  string
		CSRFToken string
	}{domain, username, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleUserStats returns the HTMX partial for inline user stats.
func (h *WebHandler) HandleUserStats(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	username := r.PathValue("username")

	// Return placeholder stats - the real stats come from the stats API
	// but for the UI we just show a simple count + size
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "user-stats", struct {
		Username  string
		Count     int
		SizeHuman string
	}{username, 0, "-"}); err != nil {
		// Fallback: if stats can't be loaded, just show dashes
		_, _ = w.Write([]byte("-"))
	}
	_ = domain // used for future store integration
}
