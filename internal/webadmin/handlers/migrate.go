package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// MigrateHandler handles migration API requests. The walk itself lives in
// internal/admin (shared with userctl); this layer owns HTTP and audit.
type MigrateHandler struct {
	ops      admin.Paths
	sessions *session.Store
	logger   *slog.Logger
	auditLog *audit.Logger
}

// NewMigrateHandler creates a new migrate handler.
// dataPath is the data volume root (gid config, uid counter); domainsPath is the config volume root.
func NewMigrateHandler(domainsPath, dataPath string, sessions *session.Store, logger *slog.Logger, auditLog *audit.Logger) *MigrateHandler {
	return &MigrateHandler{
		ops:      admin.Paths{Config: domainsPath, Data: dataPath},
		sessions: sessions,
		logger:   logger,
		auditLog: auditLog,
	}
}

// migrateResult is the JSON response for POST /api/migrate/uids.
type migrateResult struct {
	DomainsMigrated int      `json:"domains_migrated"`
	UsersMigrated   int      `json:"users_migrated"`
	Errors          []string `json:"errors"`
}

// HandleMigrateUIDs walks all domains, allocates missing gids/uids, and returns a summary.
// Individual domain failures are collected and returned in the errors array; the handler
// never returns 500 for per-domain failures.
func (h *MigrateHandler) HandleMigrateUIDs(w http.ResponseWriter, r *http.Request) {
	result, err := h.ops.MigrateUIDs()
	if err != nil {
		h.logger.Error("failed to migrate uids", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read domains directory"})
		return
	}

	for _, detail := range result.Details {
		h.logger.Info("migrated", "allocation", detail)
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Entry{
			Operation: "migrate_uids",
			Target:    h.ops.Config,
			Result:    "success",
			Detail:    fmt.Sprintf("domains=%d users=%d errors=%d", result.DomainsMigrated, result.UsersMigrated, len(result.Errors)),
		})
	}

	writeJSON(w, http.StatusOK, migrateResult{
		DomainsMigrated: result.DomainsMigrated,
		UsersMigrated:   result.UsersMigrated,
		Errors:          result.Errors,
	})
}
