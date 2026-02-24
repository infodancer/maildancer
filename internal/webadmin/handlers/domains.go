package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// domainNameRe validates domain names: lowercase alphanumeric, hyphens, dots.
var domainNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// DomainHandler handles domain management API requests.
type DomainHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
}

// NewDomainHandler creates a new domain handler.
func NewDomainHandler(domainsPath string, sessions *session.Store, logger *slog.Logger) *DomainHandler {
	return &DomainHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
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
}

// HandleListDomains returns a JSON list of configured domains.
func (h *DomainHandler) HandleListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.listDomains()
	if err != nil {
		h.logger.Error("failed to list domains", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list domains"})
		return
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create domain"})
		return
	}

	sess := h.sessions.Get(r)
	admin := ""
	if sess != nil {
		admin = sess.Username
	}
	h.logger.Info("domain created",
		slog.String("domain", req.Name),
		slog.String("admin", admin),
		slog.String("remote", r.RemoteAddr))

	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "status": "created"})
}

// HandleDeleteDomain removes a domain directory.
func (h *DomainHandler) HandleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete domain"})
		return
	}

	sess := h.sessions.Get(r)
	admin := ""
	if sess != nil {
		admin = sess.Username
	}
	h.logger.Info("domain deleted",
		slog.String("domain", name),
		slog.String("admin", admin),
		slog.String("remote", r.RemoteAddr))

	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "deleted"})
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
		configPath := filepath.Join(h.domainsPath, entry.Name(), "config.toml")
		if _, err := os.Stat(configPath); err != nil {
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
func (h *DomainHandler) getDomainDetail(name, domainPath string) (*DomainDetail, error) {
	configPath := filepath.Join(domainPath, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Simple extraction of auth type and store type from TOML.
	// We read the raw file rather than importing the domain config package
	// to avoid circular dependencies and keep the webadmin self-contained.
	authType := extractTOMLValue(string(data), "type", "auth")
	storeType := extractTOMLValue(string(data), "type", "msgstore")

	userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))

	return &DomainDetail{
		Name:      name,
		AuthType:  authType,
		StoreType: storeType,
		UserCount: userCount,
	}, nil
}

// createDomain creates the domain directory structure with default config.
func (h *DomainHandler) createDomain(name, domainPath string) error {
	// Create directory structure
	keysDir := filepath.Join(domainPath, "keys")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		return fmt.Errorf("create domain directory: %w", err)
	}

	// Write default config.toml
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

	// Create empty passwd file
	passwdPath := filepath.Join(domainPath, "passwd")
	if err := os.WriteFile(passwdPath, []byte("# Users for "+name+"\n"), 0o640); err != nil {
		return fmt.Errorf("write passwd: %w", err)
	}

	// Create users directory for maildir storage
	usersDir := filepath.Join(domainPath, "users")
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
		if strings.HasPrefix(trimmed, "[") {
			inSection = false
			continue
		}
		if inSection && strings.HasPrefix(trimmed, key+" ") || inSection && strings.HasPrefix(trimmed, key+"=") {
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
