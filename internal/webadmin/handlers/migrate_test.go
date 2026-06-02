package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// newTestMigrateHandler returns a handler with separate config and data directories.
func newTestMigrateHandler(t *testing.T) (*MigrateHandler, string, string) {
	t.Helper()
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(30*time.Minute, false)
	return NewMigrateHandler(configDir, dataDir, store, slog.Default(), nil), configDir, dataDir
}

func TestMigrateUIDs_BaredomainGetsConfig(t *testing.T) {
	h, configDir, dataDir := newTestMigrateHandler(t)

	// Domain directory must exist in config volume for migration to scan it.
	domainConfigDir := filepath.Join(configDir, "example.com")
	if err := os.MkdirAll(domainConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result migrateResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.DomainsMigrated != 1 {
		t.Errorf("expected 1 domain migrated, got %d", result.DomainsMigrated)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}

	// Verify gid was written to data volume config.toml.
	dataConfigPath := filepath.Join(dataDir, "example.com", "config.toml")
	data, err := os.ReadFile(dataConfigPath)
	if err != nil {
		t.Fatalf("data config.toml not created: %v", err)
	}
	gidStr := extractTOMLValue(string(data), "gid", "domain")
	if gidStr == "" {
		t.Error("expected [domain] gid in data config.toml, not found")
	}
	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil || gid == 0 {
		t.Errorf("expected nonzero gid, got %q", gidStr)
	}
}

func TestMigrateUIDs_ExistingAuthConfigIsPreservedGidGoesToDataVolume(t *testing.T) {
	h, configDir, dataDir := newTestMigrateHandler(t)

	// Create domain with auth config in config volume (no gid section).
	domainConfigDir := filepath.Join(configDir, "example.com")
	if err := os.MkdirAll(domainConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existingConfig := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainConfigDir, "config.toml"), []byte(existingConfig), 0o640); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result migrateResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.DomainsMigrated != 1 {
		t.Errorf("expected 1 domain migrated, got %d", result.DomainsMigrated)
	}

	// Auth config.toml in config volume must be untouched.
	authData, err := os.ReadFile(filepath.Join(domainConfigDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(authData), `type = "passwd"`) {
		t.Error("auth config.toml in config volume was modified")
	}
	if extractTOMLValue(string(authData), "gid", "domain") != "" {
		t.Error("gid should not be in the config volume config.toml")
	}

	// Gid must be in data volume config.toml.
	dataConfigPath := filepath.Join(dataDir, "example.com", "config.toml")
	dataBytes, err := os.ReadFile(dataConfigPath)
	if err != nil {
		t.Fatalf("data config.toml not created: %v", err)
	}
	gidStr := extractTOMLValue(string(dataBytes), "gid", "domain")
	if gidStr == "" {
		t.Error("expected gid in data volume config.toml after migration")
	}
}

func TestMigrateUIDs_PasswdUsersGet3FieldsAllocatedUID(t *testing.T) {
	h, configDir, dataDir := newTestMigrateHandler(t)

	domainConfigDir := filepath.Join(configDir, "example.com")
	if err := os.MkdirAll(domainConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Two users: one with 3 fields (needs uid), one with 4 fields (already has uid).
	passwd := "alice:hash1:alice\nbob:hash2:bob:10001\n"
	if err := os.WriteFile(filepath.Join(domainConfigDir, "passwd"), []byte(passwd), 0o640); err != nil {
		t.Fatal(err)
	}

	// Pre-seed gid in data volume so domain migration is skipped.
	domainDataDir := filepath.Join(dataDir, "example.com")
	if err := os.MkdirAll(domainDataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDataDir, "config.toml"), []byte("[domain]\ngid = 10000\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result migrateResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.UsersMigrated != 1 {
		t.Errorf("expected 1 user migrated, got %d", result.UsersMigrated)
	}
	if result.DomainsMigrated != 0 {
		t.Errorf("expected 0 domain migrations (gid already present), got %d", result.DomainsMigrated)
	}

	// Verify alice now has a uid field; bob's uid is unchanged.
	data, err := os.ReadFile(filepath.Join(domainConfigDir, "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			t.Errorf("line missing uid field: %q", line)
			continue
		}
		uid, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil || uid == 0 {
			t.Errorf("expected nonzero uid for user %s, got %q", parts[0], parts[3])
		}
		if parts[0] == "bob" && parts[3] != "10001" {
			t.Errorf("bob's uid should be unchanged (10001), got %s", parts[3])
		}
	}
}

func TestMigrateUIDs_Idempotent(t *testing.T) {
	h, configDir, dataDir := newTestMigrateHandler(t)

	// Create domain directory in config volume.
	if err := os.MkdirAll(filepath.Join(configDir, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}

	// First run.
	req1 := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr1 := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first run: expected 200, got %d", rr1.Code)
	}
	var result1 migrateResult
	if err := json.NewDecoder(rr1.Body).Decode(&result1); err != nil {
		t.Fatalf("decode result1: %v", err)
	}

	// Record gid from first run (stored in data volume).
	dataConfigPath := filepath.Join(dataDir, "example.com", "config.toml")
	data1, _ := os.ReadFile(dataConfigPath)
	gid1 := extractTOMLValue(string(data1), "gid", "domain")

	// Second run.
	req2 := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr2 := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second run: expected 200, got %d", rr2.Code)
	}
	var result2 migrateResult
	if err := json.NewDecoder(rr2.Body).Decode(&result2); err != nil {
		t.Fatalf("decode result2: %v", err)
	}

	// Second run should report 0 domains migrated (already done).
	if result2.DomainsMigrated != 0 {
		t.Errorf("second run: expected 0 domains migrated, got %d", result2.DomainsMigrated)
	}

	// gid must not change.
	data2, _ := os.ReadFile(dataConfigPath)
	gid2 := extractTOMLValue(string(data2), "gid", "domain")
	if gid1 != gid2 {
		t.Errorf("gid changed between runs: %s -> %s", gid1, gid2)
	}
}
