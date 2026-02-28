package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/session"
	"github.com/infodancer/maildancer/internal/webadmin/uidalloc"
)

// MigrateHandler handles migration API requests.
type MigrateHandler struct {
	domainsPath string // config volume: passwd files, auth config
	dataPath    string // data volume: gid config, uid counter
	sessions    *session.Store
	logger      *slog.Logger
	auditLog    *audit.Logger
}

// NewMigrateHandler creates a new migrate handler.
// dataPath is the data volume root (gid config, uid counter); domainsPath is the config volume root.
func NewMigrateHandler(domainsPath, dataPath string, sessions *session.Store, logger *slog.Logger, auditLog *audit.Logger) *MigrateHandler {
	return &MigrateHandler{
		domainsPath: domainsPath,
		dataPath:    dataPath,
		sessions:    sessions,
		logger:      logger,
		auditLog:    auditLog,
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
	entries, err := os.ReadDir(h.domainsPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, migrateResult{Errors: []string{}})
			return
		}
		h.logger.Error("failed to read domains directory", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read domains directory"})
		return
	}

	result := migrateResult{Errors: []string{}}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden dirs (e.g. the uid counter lives at root, not in a domain dir).
		if strings.HasPrefix(name, ".") {
			continue
		}
		configDomainPath := filepath.Join(h.domainsPath, name)
		dataDir := filepath.Join(h.dataPath, name)

		domainMigrated, usersMigrated, errs := h.migrateDomain(name, configDomainPath, dataDir)
		if domainMigrated {
			result.DomainsMigrated++
		}
		result.UsersMigrated += usersMigrated
		result.Errors = append(result.Errors, errs...)
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Entry{
			Operation: "migrate_uids",
			Target:    h.domainsPath,
			Result:    "success",
			Detail:    fmt.Sprintf("domains=%d users=%d errors=%d", result.DomainsMigrated, result.UsersMigrated, len(result.Errors)),
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// migrateDomain processes a single domain.
// domainName is the bare domain name; configDomainPath is in the config volume; dataDir is in the data volume.
// Returns whether the domain gid was migrated, how many users were migrated, and any errors.
func (h *MigrateHandler) migrateDomain(domainName, configDomainPath, dataDir string) (domainMigrated bool, usersMigrated int, errs []string) {
	// Gid lives in the data volume config.toml.
	dataConfigPath := filepath.Join(dataDir, "config.toml")
	dataBytes, dataErr := os.ReadFile(dataConfigPath)
	hasDataConfig := dataErr == nil

	var gid uint32
	if hasDataConfig {
		if v := extractTOMLValue(string(dataBytes), "gid", "domain"); v != "" {
			if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
				gid = uint32(parsed)
			}
		}
	}

	if gid == 0 {
		// Allocate a new gid using the data volume counter.
		allocated, err := uidalloc.Allocate(h.dataPath)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: allocate gid: %v", domainName, err))
			return false, 0, errs
		}
		gid = allocated

		// Write gid to data volume config.toml.
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			errs = append(errs, fmt.Sprintf("%s: create data dir: %v", domainName, err))
			return false, 0, errs
		}
		dataConfig := fmt.Sprintf("[domain]\ngid = %d\n", gid)
		if err := os.WriteFile(dataConfigPath, []byte(dataConfig), 0o640); err != nil {
			errs = append(errs, fmt.Sprintf("%s: write data config.toml: %v", domainName, err))
			return false, 0, errs
		}
		domainMigrated = true
		h.logger.Info("migrated domain gid", "domain", domainName, "gid", gid)
	}

	// Migrate users missing a uid (4th field) in the config volume passwd file.
	passwdPath := filepath.Join(configDomainPath, "passwd")
	migrated, err := h.migratePasswdUIDs(configDomainPath, passwdPath)
	if err != nil {
		errs = append(errs, fmt.Sprintf("%s: migrate passwd: %v", domainName, err))
	}
	usersMigrated = migrated

	return domainMigrated, usersMigrated, errs
}

// migratePasswdUIDs scans the passwd file for users without a uid field and allocates one for each.
// Returns the number of users updated.
func (h *MigrateHandler) migratePasswdUIDs(domainPath, passwdPath string) (int, error) {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read passwd: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	migrated := 0
	changed := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 4)
		if len(parts) < 3 {
			continue
		}
		// Parts: [username, hash, mailbox, uid?]
		// Needs migration if no 4th field or uid is 0.
		needsUID := len(parts) < 4
		if !needsUID {
			if v, err := strconv.ParseUint(parts[3], 10, 32); err == nil && v == 0 {
				needsUID = true
			} else if err != nil {
				needsUID = true
			}
		}

		if !needsUID {
			continue
		}

		uid, err := uidalloc.Allocate(h.dataPath)
		if err != nil {
			return migrated, fmt.Errorf("allocate uid for %s: %w", parts[0], err)
		}

		lines[i] = fmt.Sprintf("%s:%s:%s:%d", parts[0], parts[1], parts[2], uid)
		migrated++
		changed = true
		h.logger.Info("migrated user uid", "domain", filepath.Base(domainPath), "user", parts[0], "uid", uid)
	}

	if !changed {
		return 0, nil
	}

	unlock := lockPasswd(domainPath)
	defer unlock()
	if err := writePasswdFile(passwdPath, lines); err != nil {
		return 0, fmt.Errorf("write passwd: %w", err)
	}
	return migrated, nil
}

// writeDefaultConfig writes a standard default config.toml with the given gid.
func writeDefaultConfig(configPath string, gid uint32) error {
	content := fmt.Sprintf("[domain]\ngid = %d\n\n[auth]\ntype = \"passwd\"\ncredential_backend = \"passwd\"\nkey_backend = \"keys\"\n\n[msgstore]\ntype = \"maildir\"\nbase_path = \"users\"\n", gid)
	return os.WriteFile(configPath, []byte(content), 0o640)
}

// prependDomainGID prepends a [domain] gid block to an existing config.toml that has no [domain] section.
func prependDomainGID(configPath, existing string, gid uint32) error {
	// If there's already a [domain] section (with gid=0 somehow), replace or prepend.
	// Since we only call this when gid == 0 and [domain] section was absent or gid was missing/zero,
	// always prepend.
	content := fmt.Sprintf("[domain]\ngid = %d\n\n%s", gid, existing)
	return os.WriteFile(configPath, []byte(content), 0o640)
}
