package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/keys"
	"github.com/infodancer/maildancer/internal/webadmin/rbac"
	"github.com/infodancer/maildancer/internal/webadmin/session"
	"github.com/infodancer/maildancer/internal/webadmin/uidalloc"
)

// domainNameRe validates domain names: lowercase alphanumeric, hyphens, dots.
var domainNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// DomainHandler handles domain management API requests.
type DomainHandler struct {
	domainsPath string // config volume: auth config, passwd, keys
	dataPath    string // data volume: gid config, maildirs, uid counter
	sessions    *session.Store
	logger      *slog.Logger
	roles       *rbac.RoleStore
	auditLog    *audit.Logger
}

// NewDomainHandler creates a new domain handler.
// dataPath is the data volume root (gid config, maildirs, uid counter); domainsPath is the config volume root.
// roles and auditLog may be nil (RBAC disabled / audit file disabled).
func NewDomainHandler(domainsPath, dataPath string, sessions *session.Store, logger *slog.Logger, roles *rbac.RoleStore, auditLog *audit.Logger) *DomainHandler {
	return &DomainHandler{
		domainsPath: domainsPath,
		dataPath:    dataPath,
		sessions:    sessions,
		logger:      logger,
		roles:       roles,
		auditLog:    auditLog,
	}
}

// DomainSummary is the JSON representation of a domain in list responses.
type DomainSummary struct {
	Name      string `json:"name"`
	UserCount int    `json:"user_count"`
}

// DomainDetail is the JSON representation of a single domain.
type DomainDetail struct {
	Name      string `json:"name"`
	AuthType  string `json:"auth_type"`
	StoreType string `json:"store_type"`
	UserCount int    `json:"user_count"`
	GID       uint32 `json:"gid,omitempty"`
}

// DomainKeyStatus is the JSON response for GET /api/domains/{name}/keys.
type DomainKeyStatus struct {
	Exists      bool   `json:"exists"`
	Algorithm   string `json:"algorithm,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	HasPrivate  bool   `json:"has_private"`
}

// HandleListDomains returns a JSON list of configured domains.
func (h *DomainHandler) HandleListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.listDomains()
	if err != nil {
		h.logger.Error("failed to list domains", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list domains"})
		return
	}

	// Filter by RBAC if configured
	if h.roles != nil {
		username := audit.AdminFromContext(r.Context())
		names := make([]string, len(domains))
		for i, d := range domains {
			names[i] = d.Name
		}
		allowed := h.roles.FilterDomains(username, names)
		allowedSet := make(map[string]bool, len(allowed))
		for _, n := range allowed {
			allowedSet[n] = true
		}
		filtered := domains[:0]
		for _, d := range domains {
			if allowedSet[d.Name] {
				filtered = append(filtered, d)
			}
		}
		domains = filtered
	}

	if domains == nil {
		domains = []DomainSummary{}
	}
	writeJSON(w, http.StatusOK, domains)
}

// HandleGetDomain returns details for a single domain.
func (h *DomainHandler) HandleGetDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	detail, err := h.getDomainDetail(name, domainPath)
	if err != nil {
		h.logger.Error("failed to get domain detail", "domain", name, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get domain"})
		return
	}

	writeJSON(w, http.StatusOK, detail)
}

// HandleCreateDomain creates a new domain directory with default config.
func (h *DomainHandler) HandleCreateDomain(w http.ResponseWriter, r *http.Request) {
	// Only super_admins can create domains
	if h.roles != nil {
		username := audit.AdminFromContext(r.Context())
		if !h.roles.IsSuperAdmin(username) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "super_admin required to create domains"})
			return
		}
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !isValidDomainName(req.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, req.Name)
	if dirExists(domainPath) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "domain already exists"})
		return
	}

	if err := h.createDomain(req.Name, domainPath); err != nil {
		h.logger.Error("failed to create domain", "domain", req.Name, "error", err)
		h.logAudit(r, "create_domain", req.Name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create domain"})
		return
	}

	h.logAudit(r, "create_domain", req.Name, "success", "")
	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "status": "created"})
}

// HandleDeleteDomain removes a domain directory.
func (h *DomainHandler) HandleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	// Only super_admins can delete domains
	if h.roles != nil {
		username := audit.AdminFromContext(r.Context())
		if !h.roles.IsSuperAdmin(username) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "super_admin required to delete domains"})
			return
		}
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	// Safety check: count users
	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))
	if userCount > 0 {
		// Require explicit confirmation via query param
		if r.URL.Query().Get("confirm") != "true" {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":      fmt.Sprintf("domain has %d users, add ?confirm=true to delete", userCount),
				"user_count": fmt.Sprint(userCount),
			})
			return
		}
	}

	if err := os.RemoveAll(domainPath); err != nil {
		h.logger.Error("failed to delete domain", "domain", name, "error", err)
		h.logAudit(r, "delete_domain", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete domain"})
		return
	}

	h.logAudit(r, "delete_domain", name, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "deleted"})
}

// HandleUpdateDomainConfig writes or removes a per-domain config.toml override.
// PUT /api/domains/{name}/config
// Body: {"override":false} — removes config.toml (reverts to defaults)
// Body: {"override":true,"auth_type":"...","credential_backend":"...","key_backend":"...","store_type":"...","base_path":"..."} — writes config.toml
func (h *DomainHandler) HandleUpdateDomainConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	var req struct {
		Override          bool   `json:"override"`
		AuthType          string `json:"auth_type"`
		CredentialBackend string `json:"credential_backend"`
		KeyBackend        string `json:"key_backend"`
		StoreType         string `json:"store_type"`
		BasePath          string `json:"base_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	configPath := filepath.Join(domainPath, "config.toml")
	if !req.Override {
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			h.logger.Error("failed to remove domain config", "domain", name, "error", err)
			h.logAudit(r, "update_domain_config", name, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to remove config"})
			return
		}
		h.logAudit(r, "update_domain_config", name, "success", "reverted to defaults")
		writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "defaults"})
		return
	}

	// Validate required fields
	if req.AuthType == "" || req.StoreType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "auth_type and store_type are required"})
		return
	}

	// Read existing content so unmanaged sections (outbound, dkim, etc.) are preserved.
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		h.logger.Error("failed to read domain config", "domain", name, "error", err)
		h.logAudit(r, "update_domain_config", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config"})
		return
	}

	content := existing
	content = config.PatchSectionValue(content, "auth", "type", config.QuoteString(req.AuthType))
	content = config.PatchSectionValue(content, "auth", "credential_backend", config.QuoteString(req.CredentialBackend))
	content = config.PatchSectionValue(content, "auth", "key_backend", config.QuoteString(req.KeyBackend))
	content = config.PatchSectionValue(content, "msgstore", "type", config.QuoteString(req.StoreType))
	content = config.PatchSectionValue(content, "msgstore", "base_path", config.QuoteString(req.BasePath))

	if err := writeFileAtomic(configPath, content, 0o640); err != nil {
		h.logger.Error("failed to write domain config", "domain", name, "error", err)
		h.logAudit(r, "update_domain_config", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to write config"})
		return
	}
	h.logAudit(r, "update_domain_config", name, "success", "override written")
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "override"})
}

// HandleGetDomainKeys returns the key status for a domain.
func (h *DomainHandler) HandleGetDomainKeys(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	keysDir := filepath.Join(domainPath, "keys")
	pub, err := keys.LoadPublicKey(keysDir, "domain")
	if err != nil {
		writeJSON(w, http.StatusOK, DomainKeyStatus{Exists: false})
		return
	}

	_, privErr := os.Stat(filepath.Join(keysDir, "domain.key"))
	writeJSON(w, http.StatusOK, DomainKeyStatus{
		Exists:      true,
		Algorithm:   "x25519",
		Fingerprint: keys.PublicKeyFingerprint(pub),
		HasPrivate:  privErr == nil,
	})
}

// HandleCreateDomainKeys generates a new keypair for a domain.
func (h *DomainHandler) HandleCreateDomainKeys(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required to encrypt the private key"})
		return
	}

	pub, encPriv, err := keys.GenerateKeypair(req.Password)
	if err != nil {
		h.logger.Error("failed to generate domain keypair", "domain", name, "error", err)
		h.logAudit(r, "generate_domain_keys", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate keys"})
		return
	}

	keysDir := filepath.Join(domainPath, "keys")
	if err := keys.SaveKeypair(keysDir, "domain", pub, encPriv); err != nil {
		h.logger.Error("failed to save domain keypair", "domain", name, "error", err)
		h.logAudit(r, "generate_domain_keys", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save keys"})
		return
	}

	h.logAudit(r, "generate_domain_keys", name, "success", "")
	writeJSON(w, http.StatusCreated, map[string]string{"domain": name, "status": "keys_generated", "fingerprint": keys.PublicKeyFingerprint(pub)})
}

// HandleDeleteDomainKeys removes the domain keypair.
func (h *DomainHandler) HandleDeleteDomainKeys(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	domainPath := filepath.Join(h.domainsPath, name)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	keysDir := filepath.Join(domainPath, "keys")
	if err := keys.DeleteKeypair(keysDir, "domain"); err != nil {
		h.logger.Error("failed to delete domain keys", "domain", name, "error", err)
		h.logAudit(r, "delete_domain_keys", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete keys"})
		return
	}

	h.logAudit(r, "delete_domain_keys", name, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"domain": name, "status": "keys_deleted"})
}

// checkDomainAccess returns an error if the current user cannot access the domain.
func (h *DomainHandler) checkDomainAccess(r *http.Request, domain string) error {
	if h.roles == nil {
		return nil
	}
	username := audit.AdminFromContext(r.Context())
	if h.roles.IsSuperAdmin(username) || h.roles.CanAccessDomain(username, domain) {
		return nil
	}
	return fmt.Errorf("access denied to domain %s", domain)
}

// logAudit writes an audit entry via the audit logger (if configured) and slog.
func (h *DomainHandler) logAudit(r *http.Request, operation, target, result, detail string) {
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Entry{
			Operation: operation,
			Target:    target,
			Result:    result,
			Detail:    detail,
		})
	} else {
		admin := audit.AdminFromContext(r.Context())
		h.logger.Info("audit",
			slog.String("operation", operation),
			slog.String("target", target),
			slog.String("result", result),
			slog.String("admin", admin),
			slog.String("remote", r.RemoteAddr))
	}
}

// listDomains reads the domains directory and returns summaries.
func (h *DomainHandler) listDomains() ([]DomainSummary, error) {
	entries, err := os.ReadDir(h.domainsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DomainSummary{}, nil
		}
		return nil, fmt.Errorf("read domains directory: %w", err)
	}

	var domains []DomainSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		userCount := countPasswdEntries(filepath.Join(h.domainsPath, entry.Name(), "passwd"))
		domains = append(domains, DomainSummary{
			Name:      entry.Name(),
			UserCount: userCount,
		})
	}

	if domains == nil {
		domains = []DomainSummary{}
	}
	return domains, nil
}

// getDomainDetail reads domain config and returns detail.
// Auth/store config is read from the config volume (domainsPath); gid is read from the data volume (dataPath).
// If config.toml is absent the domain is still valid (defaults apply in smtpd/pop3d);
// we report the standard default values in that case.
func (h *DomainHandler) getDomainDetail(name, domainPath string) (*DomainDetail, error) {
	authType := "passwd"   // default
	storeType := "maildir" // default

	configPath := filepath.Join(domainPath, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err == nil {
		// Simple extraction of auth type and store type from TOML.
		// We read the raw file rather than importing the domain config package
		// to avoid circular dependencies and keep the webadmin self-contained.
		if v := extractTOMLValue(string(data), "type", "auth"); v != "" {
			authType = v
		}
		if v := extractTOMLValue(string(data), "type", "msgstore"); v != "" {
			storeType = v
		}
	}

	// Read gid from the data volume config.toml (separate from auth/msgstore config).
	var gid uint32
	dataConfigPath := filepath.Join(h.dataPath, name, "config.toml")
	if dataBytes, dataErr := os.ReadFile(dataConfigPath); dataErr == nil {
		if v := extractTOMLValue(string(dataBytes), "gid", "domain"); v != "" {
			if parsed, parseErr := strconv.ParseUint(v, 10, 32); parseErr == nil {
				gid = uint32(parsed)
			}
		}
	}

	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

	return &DomainDetail{
		Name:      name,
		AuthType:  authType,
		StoreType: storeType,
		UserCount: userCount,
		GID:       gid,
	}, nil
}

// createDomain creates the domain directory structure with default config.
// Config files (auth config, passwd, keys) go in the config volume (domainsPath).
// Data files (gid config, maildirs) go in the data volume (dataPath).
func (h *DomainHandler) createDomain(name, domainPath string) error {
	// Create config volume directory structure.
	keysDir := filepath.Join(domainPath, "keys")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		return fmt.Errorf("create domain directory: %w", err)
	}

	// Write auth/msgstore config.toml to config volume (no gid here).
	configContent := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	configPath := filepath.Join(domainPath, "config.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Create empty passwd file in config volume.
	passwdPath := filepath.Join(domainPath, "passwd")
	if err := os.WriteFile(passwdPath, []byte("# Users for "+name+"\n"), 0o640); err != nil {
		return fmt.Errorf("write passwd: %w", err)
	}

	// Allocate a gid and write gid config to the data volume.
	gid, err := uidalloc.Allocate(h.dataPath)
	if err != nil {
		return fmt.Errorf("allocate domain gid: %w", err)
	}
	dataDir := filepath.Join(h.dataPath, name)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	dataConfig := fmt.Sprintf("[domain]\ngid = %d\n", gid)
	if err := os.WriteFile(filepath.Join(dataDir, "config.toml"), []byte(dataConfig), 0o640); err != nil {
		return fmt.Errorf("write data config: %w", err)
	}

	// Create users directory for maildir storage in data volume.
	usersDir := filepath.Join(dataDir, "users")
	if err := os.MkdirAll(usersDir, 0o750); err != nil {
		return fmt.Errorf("create users directory: %w", err)
	}

	return nil
}

// isValidDomainName checks that the name is a valid, safe domain name.
func isValidDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	// Prevent path traversal
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return domainNameRe.MatchString(name)
}

// countPasswdEntries counts non-comment, non-empty lines in a passwd file.
func countPasswdEntries(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

// extractTOMLValue does a simple line-by-line search for a key under a section.
// This avoids a full TOML parse dependency for read-only config inspection.
func extractTOMLValue(content, key, section string) string {
	inSection := false
	sectionHeader := "[" + section + "]"
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == sectionHeader {
			inSection = true
			continue
		}
		if strings.HasPrefix(trimmed, "[[") || (strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[[")) {
			inSection = false
			continue
		}
		if inSection && (strings.HasPrefix(trimmed, key+" ") || strings.HasPrefix(trimmed, key+"=")) {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}

// writeFileAtomic writes data to a file atomically via temp+rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// dirExists checks if a path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log but can't change the status at this point
		_ = err
	}
}
