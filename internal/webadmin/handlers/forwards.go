package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// ForwardHandler manages per-domain forwarding rules. Every mutation delegates
// to auth/domain (the same helpers userctl calls), so the CLI and the web UI
// cannot diverge on the 1:1 policy or the on-disk format. This layer owns only
// HTTP semantics, RBAC (wired in the router), and audit logging.
//
// Forwards live in the domain's config.toml [forwards] table -- the file the
// forwarding chain actually reads. The handler never touches per-user
// user_forwards/ (slated for sieve migration, #28).
type ForwardHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
	auditLog    *audit.Logger
}

// NewForwardHandler creates a new ForwardHandler over the config volume root.
// auditLog may be nil (file audit logging disabled).
func NewForwardHandler(domainsPath string, sessions *session.Store, logger *slog.Logger, auditLog *audit.Logger) *ForwardHandler {
	return &ForwardHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
		auditLog:    auditLog,
	}
}

// forwardEntry is one forwarding rule (localpart -> single target). The catchall
// is the localpart "*".
type forwardEntry struct {
	Localpart string `json:"localpart"`
	Target    string `json:"target"`
}

// forwardSetRequest is the JSON body accepted by the upsert endpoint.
type forwardSetRequest struct {
	Localpart string `json:"localpart"`
	Target    string `json:"target"`
}

// HandleListForwards returns the domain's forwarding rules, sorted by localpart
// for a stable rendering.
func (h *ForwardHandler) HandleListForwards(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	fwds, err := domain.ListDomainForwards(h.domainsPath, name)
	if err != nil {
		if errors.Is(err, domain.ErrDomainNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
			return
		}
		h.logger.Error("failed to list forwards", "domain", name, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list forwards"})
		return
	}

	entries := make([]forwardEntry, 0, len(fwds))
	for lp, target := range fwds {
		entries = append(entries, forwardEntry{Localpart: lp, Target: target})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Localpart < entries[j].Localpart })
	writeJSON(w, http.StatusOK, entries)
}

// HandleSetForward upserts a single forwarding rule. The 1:1 policy and address
// validation are enforced by auth/domain.SetDomainForward, so a multi-target
// submission is rejected before any write and the file is left unchanged.
func (h *ForwardHandler) HandleSetForward(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	var req forwardSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Localpart = strings.TrimSpace(req.Localpart)
	if !isValidForwardLocalpart(req.Localpart) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid localpart (use * for the catchall)"})
		return
	}

	if err := domain.SetDomainForward(h.domainsPath, name, req.Localpart, req.Target); err != nil {
		switch {
		case errors.Is(err, domain.ErrMultiTargetForward):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": domain.ErrMultiTargetForward.Error()})
		case errors.Is(err, domain.ErrInvalidForwardTarget):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": domain.ErrInvalidForwardTarget.Error()})
		case errors.Is(err, domain.ErrDomainNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		default:
			h.logger.Error("failed to set forward", "domain", name, "localpart", req.Localpart, "error", err)
			h.logAudit(r, "set_forward", req.Localpart+"@"+name, "failure", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set forward"})
		}
		return
	}

	normTarget := strings.ToLower(strings.TrimSpace(req.Target))
	h.logAudit(r, "set_forward", req.Localpart+"@"+name, "success", "target="+normTarget)
	writeJSON(w, http.StatusOK, map[string]string{"localpart": req.Localpart, "target": normTarget, "status": "saved"})
}

// HandleDeleteForward removes a forwarding rule. The catchall is deleted by
// requesting the URL-encoded localpart "*" (%2A). A missing rule is reported as
// 404 so the UI can tell the operator the entry was already gone.
func (h *ForwardHandler) HandleDeleteForward(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	localpart := strings.TrimSpace(r.PathValue("localpart"))

	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if !isValidForwardLocalpart(localpart) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid localpart"})
		return
	}

	removed, err := domain.DeleteDomainForward(h.domainsPath, name, localpart)
	if err != nil {
		if errors.Is(err, domain.ErrDomainNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
			return
		}
		h.logger.Error("failed to delete forward", "domain", name, "localpart", localpart, "error", err)
		h.logAudit(r, "delete_forward", localpart+"@"+name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete forward"})
		return
	}
	if !removed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "forward not found"})
		return
	}

	h.logAudit(r, "delete_forward", localpart+"@"+name, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"localpart": localpart, "status": "deleted"})
}

// isValidForwardLocalpart accepts the catchall "*" or a path-safe localpart.
// The localpart becomes a TOML map key, not a filesystem path, but validating
// it keeps the config readable and rejects obvious garbage.
func isValidForwardLocalpart(localpart string) bool {
	if localpart == "*" {
		return true
	}
	return admin.ValidUsername(localpart)
}

// logAudit writes an audit entry via the audit logger (if configured) and slog.
func (h *ForwardHandler) logAudit(r *http.Request, operation, target, result, detail string) {
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
