package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/internal/webadmin/session"
	"github.com/infodancer/maildancer/msgstore"
)

// StatsHandler handles mailbox statistics API requests.
type StatsHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
	// openStore opens a message store for a domain. Injected for testability.
	openStore func(domainPath string) (msgstore.MessageStore, error)
}

// NewStatsHandler creates a new stats handler.
// If openStore is nil, it uses a default that reads domain config and opens the store.
func NewStatsHandler(domainsPath string, sessions *session.Store, logger *slog.Logger, openStore func(string) (msgstore.MessageStore, error)) *StatsHandler {
	if openStore == nil {
		openStore = defaultOpenStore
	}
	return &StatsHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
		openStore:   openStore,
	}
}

// MailboxStats is the JSON representation of user mailbox statistics.
type MailboxStats struct {
	Username   string        `json:"username"`
	Count      int           `json:"message_count"`
	TotalBytes int64         `json:"total_bytes"`
	Folders    []FolderStats `json:"folders,omitempty"`
}

// FolderStats holds per-folder statistics.
type FolderStats struct {
	Name       string `json:"name"`
	Count      int    `json:"message_count"`
	TotalBytes int64  `json:"total_bytes"`
}

// HandleGetStats returns mailbox statistics for a user.
func (h *StatsHandler) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	passwdPath := filepath.Join(domainPath, "passwd")
	if !userExistsInPasswd(passwdPath, username) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	store, err := h.openStore(domainPath)
	if err != nil {
		h.logger.Error("failed to open message store", "domain", domain, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to open message store"})
		return
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	ctx := context.Background()
	stats := MailboxStats{Username: username}

	count, totalBytes, err := store.Stat(ctx, username)
	if err != nil {
		h.logger.Error("failed to stat mailbox", "user", username, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read mailbox stats"})
		return
	}
	stats.Count = count
	stats.TotalBytes = totalBytes

	// Try folder stats if the store supports it
	if folderStore, ok := store.(msgstore.FolderStore); ok {
		folders, err := folderStore.ListFolders(ctx, username)
		if err == nil {
			for _, folder := range folders {
				fc, fb, ferr := folderStore.StatFolder(ctx, username, folder)
				if ferr != nil {
					continue
				}
				stats.Folders = append(stats.Folders, FolderStats{
					Name:       folder,
					Count:      fc,
					TotalBytes: fb,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, stats)
}

// defaultOpenStore opens a message store by reading the domain config.
func defaultOpenStore(domainPath string) (msgstore.MessageStore, error) {
	configPath := filepath.Join(domainPath, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	storeType := extractTOMLValue(string(data), "type", "msgstore")
	basePath := extractTOMLValue(string(data), "base_path", "msgstore")
	if !filepath.IsAbs(basePath) {
		basePath = filepath.Join(domainPath, basePath)
	}

	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     storeType,
		BasePath: basePath,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}
