package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// OutboundHandler manages outbound transport routing configuration.
type OutboundHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
	auditLog    *audit.Logger
	mu          sync.Mutex // serializes system-wide config writes
}

// NewOutboundHandler creates a new OutboundHandler.
func NewOutboundHandler(domainsPath string, sessions *session.Store, logger *slog.Logger, auditLog *audit.Logger) *OutboundHandler {
	return &OutboundHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
		auditLog:    auditLog,
	}
}

// outboundResponse is the JSON shape returned by GET endpoints.
type outboundResponse struct {
	Strategy      string `json:"strategy"`
	Smarthost     string `json:"smarthost"`
	SmarthostUser string `json:"smarthost_user"`
	HasPassword   bool   `json:"has_password"`
	PasswordFile  string `json:"password_file"`
}

// outboundRequest is the JSON shape accepted by PUT endpoints.
type outboundRequest struct {
	Strategy      string `json:"strategy"`
	Smarthost     string `json:"smarthost"`
	SmarthostUser string `json:"smarthost_user"`
	Password      string `json:"password"`
	PasswordFile  string `json:"password_file"`
}

// HandleGetDomainOutbound returns the outbound config for a specific domain.
func (h *OutboundHandler) HandleGetDomainOutbound(w http.ResponseWriter, r *http.Request) {
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

	configPath := filepath.Join(domainPath, "config.toml")
	resp := h.readOutboundConfig(configPath, domainPath)
	writeJSON(w, http.StatusOK, resp)
}

// HandleSetDomainOutbound updates the outbound config for a specific domain.
func (h *OutboundHandler) HandleSetDomainOutbound(w http.ResponseWriter, r *http.Request) {
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

	var req outboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if err := validateOutboundRequest(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	configPath := filepath.Join(domainPath, "config.toml")
	if err := h.writeOutboundConfig(configPath, domainPath, req); err != nil {
		h.logger.Error("failed to write outbound config", "domain", name, "error", err)
		h.logAudit(r, "update_outbound", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save outbound config"})
		return
	}

	h.logAudit(r, "update_outbound", name, "success", "strategy="+req.Strategy)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// HandleGetDefaultOutbound returns the system-wide default outbound config.
func (h *OutboundHandler) HandleGetDefaultOutbound(w http.ResponseWriter, r *http.Request) {
	configPath := filepath.Join(h.domainsPath, "config.toml")
	resp := h.readOutboundConfig(configPath, h.domainsPath)
	writeJSON(w, http.StatusOK, resp)
}

// HandleSetDefaultOutbound updates the system-wide default outbound config.
func (h *OutboundHandler) HandleSetDefaultOutbound(w http.ResponseWriter, r *http.Request) {
	var req outboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if err := validateOutboundRequest(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	configPath := filepath.Join(h.domainsPath, "config.toml")
	if err := h.writeOutboundConfig(configPath, h.domainsPath, req); err != nil {
		h.logger.Error("failed to write default outbound config", "error", err)
		h.logAudit(r, "update_outbound_default", "system", "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save outbound config"})
		return
	}

	h.logAudit(r, "update_outbound_default", "system", "success", "strategy="+req.Strategy)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// readOutboundConfig reads outbound settings from a config.toml file.
// baseDir is used to check for password file existence.
func (h *OutboundHandler) readOutboundConfig(configPath, baseDir string) outboundResponse {
	resp := outboundResponse{}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return resp
	}
	content := string(data)

	resp.Strategy = extractTOMLValue(content, "strategy", "outbound")
	resp.Smarthost = extractTOMLValue(content, "smarthost", "outbound")
	resp.SmarthostUser = extractTOMLValue(content, "smarthost_user", "outbound")
	resp.PasswordFile = extractTOMLValue(content, "password_file", "outbound")

	if resp.PasswordFile != "" {
		pwPath := resp.PasswordFile
		if !filepath.IsAbs(pwPath) {
			pwPath = filepath.Join(baseDir, pwPath)
		}
		if _, err := os.Stat(pwPath); err == nil {
			resp.HasPassword = true
		}
	}

	return resp
}

// writeOutboundConfig patches outbound settings into a config.toml file.
// baseDir is used for password file writes.
func (h *OutboundHandler) writeOutboundConfig(configPath, baseDir string, req outboundRequest) error {
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	content := existing

	if req.Strategy == "direct" || req.Strategy == "" {
		// Clear outbound keys from config.
		content = config.PatchSectionValue(content, "outbound", "strategy", "")
		content = config.PatchSectionValue(content, "outbound", "smarthost", "")
		content = config.PatchSectionValue(content, "outbound", "smarthost_user", "")
		content = config.PatchSectionValue(content, "outbound", "password_file", "")

		// Remove password file if it exists.
		oldPwFile := extractTOMLValue(string(existing), "password_file", "outbound")
		if oldPwFile != "" {
			pwPath := oldPwFile
			if !filepath.IsAbs(pwPath) {
				pwPath = filepath.Join(baseDir, pwPath)
			}
			_ = os.Remove(pwPath)
		}
	} else {
		// strategy == "smarthost"
		content = config.PatchSectionValue(content, "outbound", "strategy", config.QuoteString(req.Strategy))
		content = config.PatchSectionValue(content, "outbound", "smarthost", config.QuoteString(req.Smarthost))
		content = config.PatchSectionValue(content, "outbound", "smarthost_user", config.QuoteString(req.SmarthostUser))
		content = config.PatchSectionValue(content, "outbound", "password_file", config.QuoteString(req.PasswordFile))

		// Write password file if a new password was provided.
		if req.Password != "" {
			pwPath := req.PasswordFile
			if !filepath.IsAbs(pwPath) {
				pwPath = filepath.Join(baseDir, pwPath)
			}
			if err := writeFileAtomic(pwPath, []byte(req.Password+"\n"), 0o600); err != nil {
				return err
			}
		}
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	return writeFileAtomic(configPath, content, 0o640)
}

// validateOutboundRequest checks the outbound request for required fields and path safety.
func validateOutboundRequest(req outboundRequest) error {
	switch req.Strategy {
	case "", "direct":
		// No additional fields required.
	case "smarthost":
		if req.Smarthost == "" || !strings.Contains(req.Smarthost, ":") {
			return &validationError{"smarthost must be in host:port format"}
		}
		if req.SmarthostUser == "" {
			return &validationError{"smarthost_user is required for smarthost strategy"}
		}
		if req.PasswordFile == "" {
			return &validationError{"password_file is required for smarthost strategy"}
		}
	default:
		return &validationError{"strategy must be direct, smarthost, or empty"}
	}

	// Validate password_file against path traversal.
	if req.PasswordFile != "" {
		if strings.Contains(req.PasswordFile, "..") ||
			strings.Contains(req.PasswordFile, "/") ||
			strings.Contains(req.PasswordFile, "\\") {
			return &validationError{"password_file must not contain path separators or .."}
		}
	}

	return nil
}

// validationError is a simple error type for validation failures.
type validationError struct {
	msg string
}

func (e *validationError) Error() string { return e.msg }

// logAudit writes an audit entry via the audit logger (if configured) and slog.
func (h *OutboundHandler) logAudit(r *http.Request, operation, target, result, detail string) {
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
