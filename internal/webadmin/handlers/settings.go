package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/internal/webadmin/config"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// sharedConfigSettings is the full parse target for reading general settings
// from the shared config file.
type sharedConfigSettings struct {
	Server struct {
		Hostname    string `toml:"hostname"`
		Maildir     string `toml:"maildir"`
		DomainsPath string `toml:"domains_path"`
	} `toml:"server"`
	Smtpd struct {
		LogLevel string `toml:"log_level"`
		Limits   struct {
			MaxMessageSize int `toml:"max_message_size"`
			MaxRecipients  int `toml:"max_recipients"`
		} `toml:"limits"`
	} `toml:"smtpd"`
	Pop3d struct {
		LogLevel string `toml:"log_level"`
		Limits   struct {
			MaxConnections int `toml:"max_connections"`
		} `toml:"limits"`
	} `toml:"pop3d"`
	SpamCheck struct {
		Enabled bool `toml:"enabled"`
	} `toml:"spamcheck"`
}

// SettingsHandler reads and writes server/daemon settings in the shared config file.
type SettingsHandler struct {
	configFile string
	sessions   *session.Store
	logger     *slog.Logger
	mu         sync.Mutex // serializes writes
}

// NewSettingsHandler creates a new SettingsHandler.
// configFile is the path to the shared config file (may be empty; writes return 400).
func NewSettingsHandler(configFile string, sessions *session.Store, logger *slog.Logger) *SettingsHandler {
	return &SettingsHandler{
		configFile: configFile,
		sessions:   sessions,
		logger:     logger,
	}
}

// HandleGetSettings returns all current settings from the shared config as JSON.
func (h *SettingsHandler) HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.loadSettings()
	if err != nil {
		h.logger.Error("failed to load settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"server": map[string]any{
			"hostname":     cfg.Server.Hostname,
			"maildir":      cfg.Server.Maildir,
			"domains_path": cfg.Server.DomainsPath,
		},
		"smtpd": map[string]any{
			"log_level": cfg.Smtpd.LogLevel,
			"limits": map[string]any{
				"max_message_size": cfg.Smtpd.Limits.MaxMessageSize,
				"max_recipients":   cfg.Smtpd.Limits.MaxRecipients,
			},
		},
		"pop3d": map[string]any{
			"log_level": cfg.Pop3d.LogLevel,
			"limits": map[string]any{
				"max_connections": cfg.Pop3d.Limits.MaxConnections,
			},
		},
		"spamcheck": map[string]any{
			"enabled": cfg.SpamCheck.Enabled,
		},
	})
}

// HandleSetServerSettings updates [server] section keys: hostname, maildir, domains_path.
func (h *SettingsHandler) HandleSetServerSettings(w http.ResponseWriter, r *http.Request) {
	if h.configFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_file not configured"})
		return
	}

	var req struct {
		Hostname    *string `json:"hostname"`
		Maildir     *string `json:"maildir"`
		DomainsPath *string `json:"domains_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate non-nil string fields are non-empty.
	if req.Hostname != nil && *req.Hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hostname must not be empty"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.readContent()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config"})
		return
	}

	if req.Hostname != nil {
		content = config.PatchSectionValue(content, "server", "hostname", config.QuoteString(*req.Hostname))
	}
	if req.Maildir != nil {
		content = config.PatchSectionValue(content, "server", "maildir", config.QuoteString(*req.Maildir))
	}
	if req.DomainsPath != nil {
		content = config.PatchSectionValue(content, "server", "domains_path", config.QuoteString(*req.DomainsPath))
	}

	if err := h.writeContent(content); err != nil {
		h.logger.Error("failed to save server settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	h.logger.Info("server settings updated")
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// HandleSetSmtpdSettings updates [smtpd] log_level and [smtpd.limits] keys.
func (h *SettingsHandler) HandleSetSmtpdSettings(w http.ResponseWriter, r *http.Request) {
	if h.configFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_file not configured"})
		return
	}

	var req struct {
		LogLevel       *string `json:"log_level"`
		MaxMessageSize *int    `json:"max_message_size"`
		MaxRecipients  *int    `json:"max_recipients"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.LogLevel != nil {
		if !isValidLogLevel(*req.LogLevel) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "log_level must be one of: debug, info, warn, error"})
			return
		}
	}
	if req.MaxMessageSize != nil && *req.MaxMessageSize <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_message_size must be positive"})
		return
	}
	if req.MaxRecipients != nil && *req.MaxRecipients <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_recipients must be positive"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.readContent()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config"})
		return
	}

	if req.LogLevel != nil {
		content = config.PatchSectionValue(content, "smtpd", "log_level", config.QuoteString(*req.LogLevel))
	}
	if req.MaxMessageSize != nil {
		content = config.PatchSectionValue(content, "smtpd.limits", "max_message_size", strconv.Itoa(*req.MaxMessageSize))
	}
	if req.MaxRecipients != nil {
		content = config.PatchSectionValue(content, "smtpd.limits", "max_recipients", strconv.Itoa(*req.MaxRecipients))
	}

	if err := h.writeContent(content); err != nil {
		h.logger.Error("failed to save smtpd settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	h.logger.Info("smtpd settings updated")
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// HandleSetPop3dSettings updates [pop3d] log_level and [pop3d.limits] keys.
func (h *SettingsHandler) HandleSetPop3dSettings(w http.ResponseWriter, r *http.Request) {
	if h.configFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_file not configured"})
		return
	}

	var req struct {
		LogLevel       *string `json:"log_level"`
		MaxConnections *int    `json:"max_connections"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.LogLevel != nil {
		if !isValidLogLevel(*req.LogLevel) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "log_level must be one of: debug, info, warn, error"})
			return
		}
	}
	if req.MaxConnections != nil && *req.MaxConnections <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_connections must be positive"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.readContent()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config"})
		return
	}

	if req.LogLevel != nil {
		content = config.PatchSectionValue(content, "pop3d", "log_level", config.QuoteString(*req.LogLevel))
	}
	if req.MaxConnections != nil {
		content = config.PatchSectionValue(content, "pop3d.limits", "max_connections", strconv.Itoa(*req.MaxConnections))
	}

	if err := h.writeContent(content); err != nil {
		h.logger.Error("failed to save pop3d settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	h.logger.Info("pop3d settings updated")
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// HandleSetSpamcheckSettings updates [spamcheck] enabled flag.
// Accepts {"enabled": true} (JSON boolean) or {"enabled": "on"} / {"enabled": "true"}
// (string, as sent by HTML checkbox via json-enc without hx-vals type override).
func (h *SettingsHandler) HandleSetSpamcheckSettings(w http.ResponseWriter, r *http.Request) {
	if h.configFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config_file not configured"})
		return
	}

	var req struct {
		Enabled any `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	enabled := parseBoolish(req.Enabled)

	h.mu.Lock()
	defer h.mu.Unlock()

	content, err := h.readContent()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config"})
		return
	}

	enabledVal := "false"
	if enabled {
		enabledVal = "true"
	}
	content = config.PatchSectionValue(content, "spamcheck", "enabled", enabledVal)

	if err := h.writeContent(content); err != nil {
		h.logger.Error("failed to save spamcheck settings", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	h.logger.Info("spamcheck settings updated", "enabled", enabled)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// loadSettings reads the shared config file and returns parsed settings.
// Returns zero-value struct if the file does not exist.
func (h *SettingsHandler) loadSettings() (sharedConfigSettings, error) {
	if h.configFile == "" {
		return sharedConfigSettings{}, nil
	}
	data, err := os.ReadFile(h.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return sharedConfigSettings{}, nil
		}
		return sharedConfigSettings{}, fmt.Errorf("read config file: %w", err)
	}
	var cfg sharedConfigSettings
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return sharedConfigSettings{}, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, nil
}

// readContent reads the raw bytes of the config file. Returns empty slice if
// the file does not exist.
func (h *SettingsHandler) readContent() ([]byte, error) {
	data, err := os.ReadFile(h.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []byte{}, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return data, nil
}

// writeContent writes content to the config file atomically via temp+rename.
func (h *SettingsHandler) writeContent(content []byte) error {
	dir := filepath.Dir(h.configFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".config-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
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

// parseBoolish extracts a boolean from a JSON-decoded value that may be a bool
// or the strings "on", "true", or "1" (as sent by HTML checkboxes via json-enc).
func parseBoolish(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "on" || b == "true" || b == "1"
	default:
		return false
	}
}

// isValidLogLevel returns true for accepted slog level names.
func isValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}
