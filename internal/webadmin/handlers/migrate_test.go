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

func newTestMigrateHandler(t *testing.T) (*MigrateHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30*time.Minute, false)
	return NewMigrateHandler(dir, store, slog.Default(), nil), dir
}

// createBareDomain creates a domain directory with only a users/ subdir (no config.toml, no passwd).
func createBareDomain(t *testing.T, domainsPath, name string) {
	t.Helper()
	domainDir := filepath.Join(domainsPath, name)
	if err := os.MkdirAll(filepath.Join(domainDir, "users"), 0o750); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateUIDs_BaredomainGetsConfig(t *testing.T) {
	h, dir := newTestMigrateHandler(t)
	createBareDomain(t, dir, "example.com")

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

	// Verify config.toml was created with a gid.
	configPath := filepath.Join(dir, "example.com", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config.toml not created: %v", err)
	}
	gidStr := extractTOMLValue(string(data), "gid", "domain")
	if gidStr == "" {
		t.Error("expected [domain] gid in config.toml, not found")
	}
	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil || gid == 0 {
		t.Errorf("expected nonzero gid, got %q", gidStr)
	}
}

func TestMigrateUIDs_ExistingConfigNoGidGetsGidPrepended(t *testing.T) {
	h, dir := newTestMigrateHandler(t)

	// Create domain with a config.toml that has no [domain] section.
	domainDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domainDir, 0o750); err != nil {
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
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(existingConfig), 0o640); err != nil {
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

	// Verify gid was prepended and original content preserved.
	data, err := os.ReadFile(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	gidStr := extractTOMLValue(content, "gid", "domain")
	if gidStr == "" {
		t.Error("expected gid in config.toml after migration")
	}
	if !strings.Contains(content, `type = "passwd"`) {
		t.Error("original config content should be preserved")
	}
}

func TestMigrateUIDs_PasswdUsersGet3FieldsAllocatedUID(t *testing.T) {
	h, dir := newTestMigrateHandler(t)

	domainDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domainDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Two users: one with 3 fields (needs uid), one with 4 fields (already has uid).
	passwd := "alice:hash1:alice\nbob:hash2:bob:10001\n"
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwd), 0o640); err != nil {
		t.Fatal(err)
	}
	// Domain also needs a config.toml to avoid an extra domain migration count.
	config := "[domain]\ngid = 10000\n\n[auth]\ntype = \"passwd\"\ncredential_backend = \"passwd\"\nkey_backend = \"keys\"\n\n[msgstore]\ntype = \"maildir\"\nbase_path = \"users\"\n"
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(config), 0o640); err != nil {
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
	data, err := os.ReadFile(filepath.Join(domainDir, "passwd"))
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
	h, dir := newTestMigrateHandler(t)
	createBareDomain(t, dir, "example.com")

	// First run.
	req1 := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr1 := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first run: expected 200, got %d", rr1.Code)
	}
	var result1 migrateResult
	json.NewDecoder(rr1.Body).Decode(&result1)

	// Record gid from first run.
	configPath := filepath.Join(dir, "example.com", "config.toml")
	data1, _ := os.ReadFile(configPath)
	gid1 := extractTOMLValue(string(data1), "gid", "domain")

	// Second run.
	req2 := httptest.NewRequest(http.MethodPost, "/api/migrate/uids", nil)
	rr2 := httptest.NewRecorder()
	h.HandleMigrateUIDs(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second run: expected 200, got %d", rr2.Code)
	}
	var result2 migrateResult
	json.NewDecoder(rr2.Body).Decode(&result2)

	// Second run should report 0 domains migrated (already done).
	if result2.DomainsMigrated != 0 {
		t.Errorf("second run: expected 0 domains migrated, got %d", result2.DomainsMigrated)
	}

	// gid must not change.
	data2, _ := os.ReadFile(configPath)
	gid2 := extractTOMLValue(string(data2), "gid", "domain")
	if gid1 != gid2 {
		t.Errorf("gid changed between runs: %s -> %s", gid1, gid2)
	}
}
