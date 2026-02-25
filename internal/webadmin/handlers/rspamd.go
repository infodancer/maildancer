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

	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// rspamdSettings holds the rspamd connection settings read from the shared config.
type rspamdSettings struct {
	URL      string
	Password string
}

// sharedConfigRspamd is the minimal parse target for reading rspamd settings
// from the shared config file (ignores all other sections).
type sharedConfigRspamd struct {
	SpamCheck struct {
		Checkers []struct {
			Type     string `toml:"type"`
			URL      string `toml:"url"`
			Password string `toml:"password"`
		} `toml:"checkers"`
	} `toml:"spamcheck"`
}

// RspamdHandler manages rspamd connection settings in the shared config file.
type RspamdHandler struct {
	configFile string // path to the shared config.toml
	sessions   *session.Store
	logger     *slog.Logger
	mu         sync.Mutex // serializes writes to configFile
}

// NewRspamdHandler creates a new RspamdHandler.
// configFile is the path to the shared config file (may be empty; writes return 400).
func NewRspamdHandler(configFile string, sessions *session.Store, logger *slog.Logger) *RspamdHandler {
	return &RspamdHandler{
		configFile: configFile,
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

// HandleSetRspamd saves rspamd URL and/or password to the shared config file.
// Requires super_admin (enforced at the routing layer).
// If password is omitted or empty in the request, the existing password is preserved.
func (h *RspamdHandler) HandleSetRspamd(w http.ResponseWriter, r *http.Request) {
	if h.configFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_file not configured"})
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

// loadSettings reads the shared config file and returns the rspamd checker settings.
// Returns empty settings if the file does not exist or no rspamd checker is configured.
func (h *RspamdHandler) loadSettings() (rspamdSettings, error) {
	if h.configFile == "" {
		return rspamdSettings{}, nil
	}
	data, err := os.ReadFile(h.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return rspamdSettings{}, nil
		}
		return rspamdSettings{}, fmt.Errorf("read config file: %w", err)
	}
	var cfg sharedConfigRspamd
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return rspamdSettings{}, fmt.Errorf("parse config file: %w", err)
	}
	for _, c := range cfg.SpamCheck.Checkers {
		if c.Type == "rspamd" {
			return rspamdSettings{URL: c.URL, Password: c.Password}, nil
		}
	}
	return rspamdSettings{}, nil
}

// saveSettings patches the rspamd checker block in the shared config file using
// comment-preserving in-place editing, then writes via temp+rename for atomicity.
func (h *RspamdHandler) saveSettings(settings rspamdSettings) error {
	var content []byte
	data, err := os.ReadFile(h.configFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config file: %w", err)
	}
	if err == nil {
		content = data
	}

	patched := config.PatchRspamdChecker(content, settings.URL, settings.Password)

	dir := filepath.Dir(h.configFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".config-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(patched); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, h.configFile); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename config file: %w", err)
	}
	return nil
}
