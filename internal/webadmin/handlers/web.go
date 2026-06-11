package handlers

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/admin/keys"
	"github.com/infodancer/maildancer/internal/webadmin/rbac"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// uiRspamdSettings holds rspamd display data for the settings page.
type uiRspamdSettings struct {
	URL         string
	HasPassword bool
}

// uiServerSettings holds server section display data for the settings page.
type uiServerSettings struct {
	Hostname    string
	Maildir     string
	DomainsPath string
}

// uiSmtpdSettings holds smtpd section display data for the settings page.
type uiSmtpdSettings struct {
	LogLevel       string
	MaxMessageSize int
	MaxRecipients  int
}

// uiPop3dSettings holds pop3d section display data for the settings page.
type uiPop3dSettings struct {
	LogLevel       string
	MaxConnections int
}

// uiSpamCheckSettings holds spamcheck section display data for the settings page.
type uiSpamCheckSettings struct {
	Enabled bool
}

// uiOutboundConfig holds outbound transport display data.
type uiOutboundConfig struct {
	Strategy      string
	Smarthost     string
	SmarthostUser string
	HasPassword   bool
	PasswordFile  string
	HasConfig     bool
}

// uiOutboundSettings holds outbound transport display data for the settings page.
type uiOutboundSettings struct {
	Strategy      string
	Smarthost     string
	SmarthostUser string
	HasPassword   bool
	PasswordFile  string
}

// uiDomainRow holds domain data for dashboard rendering.
type uiDomainRow struct {
	Name              string
	UserCount         int
	AuthType          string
	StoreType         string
	HasKeys           bool
	CredentialBackend string
	KeyBackend        string
	BasePath          string
	HasOverride       bool
}

// uiUserRow holds user data for domain detail rendering.
type uiUserRow struct {
	Username          string
	EncryptionEnabled bool
}

// WebHandler serves the HTML UI pages and HTMX partials.
type WebHandler struct {
	domainsPath     string
	sessions        *session.Store
	logger          *slog.Logger
	render          *Renderer
	roles           *rbac.RoleStore
	configFile      string           // path to the shared config file for rspamd settings display
	settingsHandler *SettingsHandler // for loading general settings on the settings page
	outboundHandler *OutboundHandler // for loading outbound settings on the settings page
}

// NewWebHandler creates a new web UI handler.
// roles may be nil (RBAC disabled -- all authenticated users treated as super_admin).
func NewWebHandler(domainsPath string, sessions *session.Store, logger *slog.Logger, roles *rbac.RoleStore) *WebHandler {
	return &WebHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
		render:      NewRenderer(),
		roles:       roles,
	}
}

// SetConfigFile sets the path to the shared config file so the settings page
// can display the current rspamd URL. Called after construction.
func (h *WebHandler) SetConfigFile(path string) {
	h.configFile = path
}

// SetSettingsHandler wires the SettingsHandler so the settings page can load
// all general settings for display. Called after construction.
func (h *WebHandler) SetSettingsHandler(sh *SettingsHandler) {
	h.settingsHandler = sh
}

// SetOutboundHandler wires the OutboundHandler so the settings and domain
// detail pages can display outbound transport config. Called after construction.
func (h *WebHandler) SetOutboundHandler(oh *OutboundHandler) {
	h.outboundHandler = oh
}

// HandleDNSWizard renders the DNS setup wizard page.
func (h *WebHandler) HandleDNSWizard(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		http.Error(w, "Invalid domain name", http.StatusBadRequest)
		return
	}

	if h.roles != nil {
		username := h.currentUsername(r)
		if !h.roles.IsSuperAdmin(username) && !h.roles.CanAccessDomain(username, name) {
			http.Error(w, "Forbidden: insufficient domain access", http.StatusForbidden)
			return
		}
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Pre-fill hostname and IP from server settings.
	hostname := ""
	serverIP := ""
	if h.settingsHandler != nil {
		if cfg, err := h.settingsHandler.loadSettings(); err == nil {
			hostname = cfg.Server.Hostname
		}
	}

	pd := h.pageData(r, struct {
		Domain   string
		Hostname string
		ServerIP string
	}{
		Domain:   name,
		Hostname: hostname,
		ServerIP: serverIP,
	})
	if err := h.render.Render(w, "dns", pd); err != nil {
		h.logger.Error("failed to render DNS wizard", "error", err)
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

// currentUsername returns the authenticated admin's username from session.
func (h *WebHandler) currentUsername(r *http.Request) string {
	return audit.AdminFromContext(r.Context())
}

// HandleDashboard renders the main dashboard with domain list.
func (h *WebHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(h.domainsPath)
	if err != nil && !os.IsNotExist(err) {
		h.logger.Error("failed to read domains directory", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	username := h.currentUsername(r)

	var domains []uiDomainRow
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainName := entry.Name()
		domainPath := filepath.Join(h.domainsPath, domainName)

		// Apply RBAC filter
		if h.roles != nil && !h.roles.IsSuperAdmin(username) && !h.roles.CanAccessDomain(username, domainName) {
			continue
		}

		// Set defaults; override from config.toml if it exists.
		authType := "passwd"
		storeType := "maildir"
		credentialBackend := "passwd"
		keyBackend := "keys"
		basePath := "users"
		hasOverride := false

		configPath := filepath.Join(domainPath, "config.toml")
		if data, err := os.ReadFile(configPath); err == nil {
			hasOverride = true
			if v := extractTOMLValue(string(data), "type", "auth"); v != "" {
				authType = v
			}
			if v := extractTOMLValue(string(data), "type", "msgstore"); v != "" {
				storeType = v
			}
			if v := extractTOMLValue(string(data), "credential_backend", "auth"); v != "" {
				credentialBackend = v
			}
			if v := extractTOMLValue(string(data), "key_backend", "auth"); v != "" {
				keyBackend = v
			}
			if v := extractTOMLValue(string(data), "base_path", "msgstore"); v != "" {
				basePath = v
			}
		}

		userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

		// Check for domain-level keys
		_, pubErr := keys.LoadPublicKey(filepath.Join(domainPath, "keys"), "domain")

		domains = append(domains, uiDomainRow{
			Name:              domainName,
			UserCount:         userCount,
			AuthType:          authType,
			StoreType:         storeType,
			HasKeys:           pubErr == nil,
			CredentialBackend: credentialBackend,
			KeyBackend:        keyBackend,
			BasePath:          basePath,
			HasOverride:       hasOverride,
		})
	}

	if domains == nil {
		domains = []uiDomainRow{}
	}

	isSuperAdmin := h.roles == nil || h.roles.IsSuperAdmin(username)

	pd := h.pageData(r, nil)
	pd.Data = struct {
		Domains      []uiDomainRow
		IsSuperAdmin bool
	}{Domains: domains, IsSuperAdmin: isSuperAdmin}
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

	// RBAC check
	if h.roles != nil {
		username := h.currentUsername(r)
		if !h.roles.IsSuperAdmin(username) && !h.roles.CanAccessDomain(username, name) {
			http.Error(w, "Forbidden: insufficient domain access", http.StatusForbidden)
			return
		}
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// Read domain config -- set defaults, override from config.toml if present.
	authType := "passwd"
	storeType := "maildir"
	credentialBackend := "passwd"
	keyBackend := "keys"
	basePath := "users"
	hasOverride := false

	configPath := filepath.Join(domainPath, "config.toml")
	if configData, err := os.ReadFile(configPath); err == nil {
		hasOverride = true
		if v := extractTOMLValue(string(configData), "type", "auth"); v != "" {
			authType = v
		}
		if v := extractTOMLValue(string(configData), "type", "msgstore"); v != "" {
			storeType = v
		}
		if v := extractTOMLValue(string(configData), "credential_backend", "auth"); v != "" {
			credentialBackend = v
		}
		if v := extractTOMLValue(string(configData), "key_backend", "auth"); v != "" {
			keyBackend = v
		}
		if v := extractTOMLValue(string(configData), "base_path", "msgstore"); v != "" {
			basePath = v
		}
	}

	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

	// Domain key status
	keysDir := filepath.Join(domainPath, "keys")
	domainPub, pubErr := keys.LoadPublicKey(keysDir, "domain")
	domainKeyFingerprint := ""
	if pubErr == nil {
		domainKeyFingerprint = keys.PublicKeyFingerprint(domainPub)
	}

	users := h.listUsersForUI(domainPath)

	// Read outbound transport config.
	outbound := uiOutboundConfig{}
	if configData, err := os.ReadFile(configPath); err == nil {
		content := string(configData)
		outbound.Strategy = extractTOMLValue(content, "strategy", "outbound")
		outbound.Smarthost = extractTOMLValue(content, "smarthost", "outbound")
		outbound.SmarthostUser = extractTOMLValue(content, "smarthost_user", "outbound")
		outbound.PasswordFile = extractTOMLValue(content, "password_file", "outbound")
		outbound.HasConfig = outbound.Strategy != ""
		if outbound.PasswordFile != "" {
			pwPath := outbound.PasswordFile
			if !filepath.IsAbs(pwPath) {
				pwPath = filepath.Join(domainPath, pwPath)
			}
			if _, err := os.Stat(pwPath); err == nil {
				outbound.HasPassword = true
			}
		}
	}

	pd := h.pageData(r, nil)
	pd.Data = struct {
		Domain               uiDomainRow
		Users                []uiUserRow
		DomainKeyFingerprint string
		IsSuperAdmin         bool
		Outbound             uiOutboundConfig
	}{
		Domain: uiDomainRow{
			Name:              name,
			UserCount:         userCount,
			AuthType:          authType,
			StoreType:         storeType,
			HasKeys:           pubErr == nil,
			CredentialBackend: credentialBackend,
			KeyBackend:        keyBackend,
			BasePath:          basePath,
			HasOverride:       hasOverride,
		},
		Users:                users,
		DomainKeyFingerprint: domainKeyFingerprint,
		IsSuperAdmin:         h.roles == nil || h.roles.IsSuperAdmin(h.currentUsername(r)),
		Outbound:             outbound,
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

		_, err := keys.LoadPublicKey(keysDir, username)

		users = append(users, uiUserRow{
			Username:          username,
			EncryptionEnabled: err == nil,
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

// HandleGenerateKeysForm returns the HTMX partial for the user key generation form.
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

// HandleGenerateDomainKeysForm returns the HTMX partial for domain key generation.
func (h *WebHandler) HandleGenerateDomainKeysForm(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	sess := h.sessions.Get(r)
	csrfToken := ""
	if sess != nil {
		csrfToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "generate-domain-keys-form", struct {
		Domain    string
		CSRFToken string
	}{domain, csrfToken}); err != nil {
		h.logger.Error("failed to render partial", "error", err)
	}
}

// HandleSettings renders the settings page (rspamd connection, server, smtpd, pop3d, spamcheck).
func (h *WebHandler) HandleSettings(w http.ResponseWriter, r *http.Request) {
	// Load rspamd settings for display (read-only; writes go through /api/rspamd).
	rspamd := uiRspamdSettings{}
	if h.configFile != "" {
		if rh := NewRspamdHandler(h.configFile, h.sessions, h.logger); rh != nil {
			if s, err := rh.loadSettings(); err == nil {
				rspamd.URL = s.URL
				rspamd.HasPassword = s.Password != ""
			}
		}
	}

	// Load general settings via the SettingsHandler.
	var server uiServerSettings
	var smtpd uiSmtpdSettings
	var pop3d uiPop3dSettings
	var spamCheck uiSpamCheckSettings
	if h.settingsHandler != nil {
		if cfg, err := h.settingsHandler.loadSettings(); err == nil {
			server = uiServerSettings{
				Hostname:    cfg.Server.Hostname,
				Maildir:     cfg.Server.Maildir,
				DomainsPath: cfg.Server.DomainsPath,
			}
			smtpd = uiSmtpdSettings{
				LogLevel:       cfg.Smtpd.LogLevel,
				MaxMessageSize: cfg.Smtpd.Limits.MaxMessageSize,
				MaxRecipients:  cfg.Smtpd.Limits.MaxRecipients,
			}
			pop3d = uiPop3dSettings{
				LogLevel:       cfg.Pop3d.LogLevel,
				MaxConnections: cfg.Pop3d.Limits.MaxConnections,
			}
			spamCheck = uiSpamCheckSettings{
				Enabled: cfg.SpamCheck.Enabled,
			}
		}
	}

	// Load system-wide outbound transport config.
	outbound := uiOutboundSettings{}
	if h.outboundHandler != nil {
		configPath := filepath.Join(h.domainsPath, "config.toml")
		if data, err := os.ReadFile(configPath); err == nil {
			content := string(data)
			outbound.Strategy = extractTOMLValue(content, "strategy", "outbound")
			outbound.Smarthost = extractTOMLValue(content, "smarthost", "outbound")
			outbound.SmarthostUser = extractTOMLValue(content, "smarthost_user", "outbound")
			outbound.PasswordFile = extractTOMLValue(content, "password_file", "outbound")
			if outbound.PasswordFile != "" {
				pwPath := outbound.PasswordFile
				if !filepath.IsAbs(pwPath) {
					pwPath = filepath.Join(h.domainsPath, pwPath)
				}
				if _, err := os.Stat(pwPath); err == nil {
					outbound.HasPassword = true
				}
			}
		}
	}

	isSuperAdmin := h.roles == nil || h.roles.IsSuperAdmin(h.currentUsername(r))
	pd := h.pageData(r, struct {
		IsSuperAdmin bool
		Rspamd       uiRspamdSettings
		Server       uiServerSettings
		Smtpd        uiSmtpdSettings
		Pop3d        uiPop3dSettings
		SpamCheck    uiSpamCheckSettings
		Outbound     uiOutboundSettings
	}{
		IsSuperAdmin: isSuperAdmin,
		Rspamd:       rspamd,
		Server:       server,
		Smtpd:        smtpd,
		Pop3d:        pop3d,
		SpamCheck:    spamCheck,
		Outbound:     outbound,
	})
	if err := h.render.Render(w, "settings", pd); err != nil {
		h.logger.Error("failed to render settings page", "error", err)
	}
}

// HandleUserStats returns the HTMX partial for inline user stats.
func (h *WebHandler) HandleUserStats(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.RenderPartial(w, "user-stats", struct {
		Username  string
		Count     int
		SizeHuman string
	}{username, 0, "-"}); err != nil {
		_, _ = w.Write([]byte("-"))
	}
}
