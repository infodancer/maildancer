package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// rspamdSettings holds the rspamd connection configuration stored in rspamd.toml.
type rspamdSettings struct {
	URL      string `toml:"url"`
	Password string `toml:"password"`
}

// rspamdFile is the on-disk TOML structure.
type rspamdFile struct {
	Rspamd rspamdSettings `toml:"rspamd"`
}

// RspamdHandler manages rspamd connection settings.
type RspamdHandler struct {
	rspamdFile string
	sessions   *session.Store
	logger     *slog.Logger
	mu         sync.Mutex // serializes writes to rspamdFile
}

// NewRspamdHandler creates a new RspamdHandler.
// rspamdFile is the path to the shared rspamd.toml (may be empty; writes will return 400).
func NewRspamdHandler(rspamdFile string, sessions *session.Store, logger *slog.Logger) *RspamdHandler {
	return &RspamdHandler{
		rspamdFile: rspamdFile,
		sessions:   sessions,
		logger:     logger,
	}
}

// HandleGetRspamd returns the current rspamd URL and whether a password is configured.
// The password value itself is never returned.
func (h *RspamdHandler) HandleGetRspamd(w http.ResponseWriter, r *http.Request) {
	settings, err := h.loadSettings()
	if err != nil {
		h.logger.Error("failed to load rspamd settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":          settings.URL,
		"has_password": settings.Password != "",
	})
}

// HandleSetRspamd saves rspamd URL and/or password to the rspamd settings file.
// Requires super_admin (enforced at the routing layer).
// If password is omitted or empty in the request, the existing password is preserved.
func (h *RspamdHandler) HandleSetRspamd(w http.ResponseWriter, r *http.Request) {
	if h.rspamdFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rspamd_file not configured"})
		return
	}

	var req struct {
		URL      string `json:"url"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Load existing settings to preserve password if not supplied.
	existing, err := h.loadSettings()
	if err != nil {
		h.logger.Error("failed to load existing rspamd settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load settings"})
		return
	}

	settings := rspamdSettings{
		URL:      req.URL,
		Password: existing.Password, // preserve unless caller provides a new one
	}
	if req.Password != "" {
		settings.Password = req.Password
	}

	if err := h.saveSettings(settings); err != nil {
		h.logger.Error("failed to save rspamd settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	h.logger.Info("rspamd settings updated",
		slog.String("url", settings.URL),
		slog.Bool("password_set", settings.Password != ""))
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// loadSettings reads rspamd.toml and returns the settings.
// Returns empty settings if the file does not exist.
func (h *RspamdHandler) loadSettings() (rspamdSettings, error) {
	if h.rspamdFile == "" {
		return rspamdSettings{}, nil
	}
	data, err := os.ReadFile(h.rspamdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return rspamdSettings{}, nil
		}
		return rspamdSettings{}, fmt.Errorf("read rspamd file: %w", err)
	}
	var f rspamdFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return rspamdSettings{}, fmt.Errorf("parse rspamd file: %w", err)
	}
	return f.Rspamd, nil
}

// saveSettings writes settings to rspamd.toml using temp+rename for atomicity.
func (h *RspamdHandler) saveSettings(settings rspamdSettings) error {
	data, err := toml.Marshal(rspamdFile{Rspamd: settings})
	if err != nil {
		return fmt.Errorf("marshal rspamd settings: %w", err)
	}

	dir := filepath.Dir(h.rspamdFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create rspamd config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".rspamd-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, h.rspamdFile); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename rspamd file: %w", err)
	}
	return nil
}
