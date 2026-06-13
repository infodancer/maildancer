package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// UserHandler handles user management API requests. All filesystem-level
// operations delegate to internal/admin (shared with userctl); this layer
// owns HTTP semantics, RBAC, and audit logging.
type UserHandler struct {
	ops      admin.Paths
	sessions *session.Store
	logger   *slog.Logger
	auditLog *audit.Logger
}

// NewUserHandler creates a new user handler.
// dataPath is the data volume root (maildirs, uid counter); domainsPath is the config volume root.
// auditLog may be nil (audit file logging disabled).
func NewUserHandler(domainsPath, dataPath string, sessions *session.Store, logger *slog.Logger, auditLog *audit.Logger) *UserHandler {
	return &UserHandler{
		ops:      admin.Paths{Config: domainsPath, Data: dataPath},
		sessions: sessions,
		logger:   logger,
		auditLog: auditLog,
	}
}

// UserSummary is the JSON representation of a user.
type UserSummary struct {
	Username          string `json:"username"`
	Mailbox           string `json:"mailbox"`
	EncryptionEnabled bool   `json:"encryption_enabled"`
	UID               uint32 `json:"uid,omitempty"`
}

// HandleListUsers returns a JSON list of users in a domain.
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	users, err := h.ops.ListUsers(domain)
	if err != nil {
		if errors.Is(err, admin.ErrDomainNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
			return
		}
		h.logger.Error("failed to list users", "domain", domain, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
		return
	}

	summaries := make([]UserSummary, 0, len(users))
	for _, u := range users {
		summaries = append(summaries, UserSummary{
			Username:          u.Username,
			Mailbox:           u.Mailbox,
			EncryptionEnabled: u.HasKeys,
			UID:               u.UID,
		})
	}
	writeJSON(w, http.StatusOK, summaries)
}

// HandleCreateUser creates a new user in a domain.
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if !h.ops.DomainExists(domain) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		GenerateKeys bool   `json:"generate_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if !isValidUsername(req.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid username"})
		return
	}
	if !isStrongPassword(req.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password must be at least %d characters", admin.MinPasswordLength),
		})
		return
	}

	result, err := h.ops.CreateUser(domain, req.Username, req.Password, req.GenerateKeys)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrUserExists):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "user already exists"})
		default:
			h.logger.Error("failed to create user", "user", req.Username, "domain", domain, "error", err)
			h.logAudit(r, "create_user", req.Username+"@"+domain, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		}
		return
	}
	for _, warning := range result.Warnings {
		h.logger.Error("create user warning", "user", req.Username, "domain", domain, "warning", warning)
	}

	h.logAudit(r, "create_user", req.Username+"@"+domain, "success", "")
	writeJSON(w, http.StatusCreated, map[string]any{
		"username":       req.Username,
		"status":         "created",
		"keys_generated": result.KeysGenerated,
	})
}

// HandleDeleteUser removes a user from a domain.
func (h *UserHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid username"})
		return
	}

	if err := h.ops.DeleteUser(domain, username); err != nil {
		switch {
		case errors.Is(err, admin.ErrDomainNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		case errors.Is(err, admin.ErrUserNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		default:
			h.logger.Error("failed to delete user", "user", username, "domain", domain, "error", err)
			h.logAudit(r, "delete_user", username+"@"+domain, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
		}
		return
	}

	h.logAudit(r, "delete_user", username+"@"+domain, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "deleted"})
}

// HandleResetPassword changes a user's password.
func (h *UserHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	var req struct {
		Password       string `json:"password"`
		RegenerateKeys bool   `json:"regenerate_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if !isStrongPassword(req.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password must be at least %d characters", admin.MinPasswordLength),
		})
		return
	}

	// An admin reset cannot re-seal a user's encryption key (the current
	// password is unknown). Keyed users therefore require the explicit
	// regenerate_keys confirmation: the keypair is replaced and previously
	// encrypted mail becomes unreadable.
	if req.RegenerateKeys {
		fingerprint, err := h.ops.ResetPasswordRegenKeys(domain, username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, admin.ErrDomainNotFound), errors.Is(err, admin.ErrUserNotFound):
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			default:
				h.logger.Error("failed to update password", "user", username, "domain", domain, "error", err)
				h.logAudit(r, "reset_password", username+"@"+domain, "failure", err.Error())
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
			}
			return
		}
		h.logAudit(r, "reset_password_regen_keys", username+"@"+domain, "success", "fingerprint="+fingerprint)
		resp := map[string]string{"username": username, "status": "password_updated"}
		if fingerprint != "" {
			resp["warning"] = "encryption keypair regenerated; previously encrypted mail is no longer readable"
			resp["fingerprint"] = fingerprint
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if err := h.ops.ResetPassword(domain, username, req.Password); err != nil {
		switch {
		case errors.Is(err, admin.ErrUserHasKeys):
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "user has encryption keys: resetting the password requires regenerating them (previously encrypted mail becomes unreadable); confirm with regenerate_keys",
			})
		case errors.Is(err, admin.ErrDomainNotFound), errors.Is(err, admin.ErrUserNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		default:
			h.logger.Error("failed to update password", "user", username, "domain", domain, "error", err)
			h.logAudit(r, "reset_password", username+"@"+domain, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
		}
		return
	}

	h.logAudit(r, "reset_password", username+"@"+domain, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "password_updated"})
}

// HandleGetKeys returns encryption key status for a user.
func (h *UserHandler) HandleGetKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	status, err := h.ops.UserKeyStatus(domain, username)
	if err != nil {
		// Domain absence reads as "no keys", preserving the prior contract.
		status = &admin.KeyStatus{}
	}

	resp := map[string]any{
		"username":           username,
		"encryption_enabled": status.Exists,
		"has_public_key":     status.Exists,
	}
	if status.Exists {
		resp["fingerprint"] = status.Fingerprint
		resp["has_private_key"] = status.HasPrivate
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleCreateKeys generates a new keypair for a user.
func (h *UserHandler) HandleCreateKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if _, err := h.ops.CreateUserKeys(domain, username, req.Password); err != nil {
		switch {
		case errors.Is(err, admin.ErrPasswordRequired):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required to encrypt the private key"})
		case errors.Is(err, admin.ErrDomainNotFound), errors.Is(err, admin.ErrUserNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		default:
			h.logger.Error("failed to generate keys", "user", username, "domain", domain, "error", err)
			h.logAudit(r, "generate_user_keys", username+"@"+domain, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate keys"})
		}
		return
	}

	h.logAudit(r, "generate_user_keys", username+"@"+domain, "success", "")
	writeJSON(w, http.StatusCreated, map[string]string{"username": username, "status": "keys_generated"})
}

// HandleDeleteKeys removes encryption keys for a user.
func (h *UserHandler) HandleDeleteKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	if err := h.ops.DeleteUserKeys(domain, username); err != nil && !errors.Is(err, admin.ErrDomainNotFound) {
		h.logger.Error("failed to delete keys", "user", username, "domain", domain, "error", err)
		h.logAudit(r, "delete_user_keys", username+"@"+domain, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete keys"})
		return
	}

	h.logAudit(r, "delete_user_keys", username+"@"+domain, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "keys_removed"})
}

// logAudit writes an audit entry.
func (h *UserHandler) logAudit(r *http.Request, operation, target, result, detail string) {
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Entry{
			Operation: operation,
			Target:    target,
			Result:    result,
			Detail:    detail,
		})
	} else {
		adminUser := audit.AdminFromContext(r.Context())
		h.logger.Info("audit",
			slog.String("operation", operation),
			slog.String("target", target),
			slog.String("result", result),
			slog.String("admin", adminUser),
			slog.String("remote", r.RemoteAddr))
	}
}

// isValidUsername checks that the username is safe.
func isValidUsername(name string) bool {
	return admin.ValidUsername(name)
}

// isStrongPassword checks minimum password requirements.
func isStrongPassword(password string) bool {
	return admin.ValidPassword(password)
}

// userExistsInPasswd checks if a username exists in the passwd file.
// Retained for read-only callers (stats.go); mutating paths go through
// internal/admin.
func userExistsInPasswd(path, username string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if parts[0] == username {
			return true
		}
	}
	return false
}
