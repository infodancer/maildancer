package handlers

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// DomainStats holds per-domain statistics for the dashboard.
type DomainStats struct {
	Name      string `json:"name"`
	UserCount int    `json:"user_count"`
	HasKeys   bool   `json:"has_keys"`
}

// DashboardStats is the response for GET /api/dashboard.
type DashboardStats struct {
	DomainCount int           `json:"domain_count"`
	TotalUsers  int           `json:"total_users"`
	ByDomain    []DomainStats `json:"by_domain"`
}

// DashboardHandler handles the /api/dashboard endpoint.
type DashboardHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
}

// NewDashboardHandler creates a new dashboard handler.
func NewDashboardHandler(domainsPath string, sessions *session.Store, logger *slog.Logger) *DashboardHandler {
	return &DashboardHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
	}
}

// HandleGetDashboard handles GET /api/dashboard and returns JSON stats.
func (h *DashboardHandler) HandleGetDashboard(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(h.domainsPath)
	if err != nil && !os.IsNotExist(err) {
		h.logger.Error("failed to read domains directory", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read domains"})
		return
	}

	var byDomain []DomainStats
	totalUsers := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainPath := filepath.Join(h.domainsPath, entry.Name())
		configPath := filepath.Join(domainPath, "config.toml")
		if _, err := os.Stat(configPath); err != nil {
			continue
		}

		userCount := countPasswdEntries(filepath.Join(domainPath, "passwd"))
		hasKeys := domainHasPubKeys(filepath.Join(domainPath, "keys"))
		totalUsers += userCount

		byDomain = append(byDomain, DomainStats{
			Name:      entry.Name(),
			UserCount: userCount,
			HasKeys:   hasKeys,
		})
	}

	if byDomain == nil {
		byDomain = []DomainStats{}
	}

	writeJSON(w, http.StatusOK, DashboardStats{
		DomainCount: len(byDomain),
		TotalUsers:  totalUsers,
		ByDomain:    byDomain,
	})
}

// domainHasPubKeys returns true if the keys directory contains any .pub files.
func domainHasPubKeys(keysDir string) bool {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".pub" {
			return true
		}
	}
	return false
}
