package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/identity"
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

	// Verify gid was written to the authoritative {config}/gid.toml.
	gid, err := identity.DomainGID(configDir, "example.com")
	if err != nil || gid == 0 {
		t.Errorf("expected a gid in gid.toml, got gid=%d err=%v", gid, err)
	}
	_ = dataDir
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

	// Auth config.toml in config volume must be untouched and carry no gid.
	authData, err := os.ReadFile(filepath.Join(domainConfigDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(authData), `type = "passwd"`) {
		t.Error("auth config.toml in config volume was modified")
	}
	if strings.Contains(string(authData), "gid") {
		t.Error("gid must not be in the per-domain config.toml")
	}

	// Gid lives in the authoritative {config}/gid.toml.
	if gid, err := identity.DomainGID(configDir, "example.com"); err != nil || gid == 0 {
		t.Errorf("expected a gid in gid.toml after migration, got gid=%d err=%v", gid, err)
	}
	_ = dataDir
}

func TestMigrateUIDs_PasswdUsersGet3FieldsAllocatedUID(t *testing.T) {
	h, configDir, dataDir := newTestMigrateHandler(t)

	domainConfigDir := filepath.Join(configDir, "example.com")
	if err := os.MkdirAll(domainConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Two users: alice has no uid anywhere; bob carries a legacy passwd uid.
	passwd := "alice:hash1:alice\nbob:hash2:bob:10001\n"
	if err := os.WriteFile(filepath.Join(domainConfigDir, "passwd"), []byte(passwd), 0o640); err != nil {
		t.Fatal(err)
	}

	// Pre-seed the gid in the authoritative gid.toml so domain migration is
	// skipped and only the user uids migrate.
	if err := identity.NewManager(configDir, dataDir).SetDomainGID("example.com", 10000); err != nil {
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
	// Both users gain a uid.toml entry: alice allocated, bob's passwd uid adopted.
	if result.UsersMigrated != 2 {
		t.Errorf("expected 2 users migrated, got %d", result.UsersMigrated)
	}
	if result.DomainsMigrated != 0 {
		t.Errorf("expected 0 domain migrations (gid already present), got %d", result.DomainsMigrated)
	}

	// uid is authoritative in uid.toml; the passwd file is left untouched
	// (still 3-field for alice). bob's legacy uid is adopted unchanged.
	aliceUID, err := identity.UserUID(configDir, "example.com", "alice")
	if err != nil || aliceUID == 0 {
		t.Errorf("alice has no uid in uid.toml: uid=%d err=%v", aliceUID, err)
	}
	bobUID, err := identity.UserUID(configDir, "example.com", "bob")
	if err != nil || bobUID != 10001 {
		t.Errorf("bob's adopted uid = %d (err=%v), want 10001", bobUID, err)
	}
	if pw, _ := os.ReadFile(filepath.Join(domainConfigDir, "passwd")); !strings.Contains(string(pw), "alice:hash1:alice\n") {
		t.Errorf("alice's passwd line should be unchanged 3-field, got:\n%s", pw)
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

	// Record gid from first run (stored in {config}/gid.toml).
	gid1, err := identity.DomainGID(configDir, "example.com")
	if err != nil {
		t.Fatalf("gid after first run: %v", err)
	}
	_ = dataDir

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
	gid2, err := identity.DomainGID(configDir, "example.com")
	if err != nil {
		t.Fatalf("gid after second run: %v", err)
	}
	if gid1 != gid2 {
		t.Errorf("gid changed between runs: %d -> %d", gid1, gid2)
	}
}
