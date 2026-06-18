package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth/identity"
)

// setupDomain writes a domain config + identity maps under a fresh config tree
// and returns the config-tree root and domain dir.
func setupDomain(t *testing.T, domainName, configTOML string, gid uint32, users map[string]uint32) (configDir, domainDir string) {
	t.Helper()
	configDir = t.TempDir()
	domainDir = filepath.Join(configDir, domainName)
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if configTOML != "" {
		if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(configTOML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := identity.NewManager(configDir, t.TempDir())
	if err := m.SetDomainGID(domainName, gid); err != nil {
		t.Fatal(err)
	}
	for u, uid := range users {
		if err := m.SetUserUID(domainName, u, uid); err != nil {
			t.Fatal(err)
		}
	}
	return configDir, domainDir
}

func TestLookup_ValidUser(t *testing.T) {
	cfg := `[msgstore]
base_path = "users"
type = "maildir"

[auth]
credential_backend = "passwd"
`
	configDir, domainDir := setupDomain(t, "example.com", cfg, 5000, map[string]uint32{"alice": 1001})

	info, err := Lookup(configDir, "", "alice", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.UID != 1001 {
		t.Errorf("UID = %d, want 1001", info.UID)
	}
	if info.GID != 5000 {
		t.Errorf("GID = %d, want 5000", info.GID)
	}
	if info.StoreType != "maildir" {
		t.Errorf("StoreType = %q, want %q", info.StoreType, "maildir")
	}
	if want := filepath.Join(domainDir, "users"); info.BasePath != want {
		t.Errorf("BasePath = %q, want %q", info.BasePath, want)
	}
}

// TestLookup_MissingUID: a user with no uid.toml entry is a hard error, never a
// default. (Identity is not subject to fallback.)
func TestLookup_MissingUID(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "", 5000, nil)
	if _, err := Lookup(configDir, "", "nonexistent", "example.com"); err == nil {
		t.Fatal("expected hard error for user with no uid allocation")
	}
}

// TestLookup_MissingGID: a domain with no gid.toml entry is a hard error. This
// is the inverse of the homelab bug -- spawning with an unresolved gid is
// refused outright rather than defaulting to 0.
func TestLookup_MissingGID(t *testing.T) {
	configDir := t.TempDir()
	domainDir := filepath.Join(configDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// uid allocated, but no gid for the domain.
	m := identity.NewManager(configDir, t.TempDir())
	if err := m.SetUserUID("example.com", "bob", 2001); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(configDir, "", "bob", "example.com"); err == nil {
		t.Fatal("expected hard error for domain with no gid allocation")
	}
}

// TestLookup_DataPath: a relative base_path resolves against the data tree, not
// the config tree, when domainsDataPath is set.
func TestLookup_DataPath(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "", 10013, map[string]uint32{"dave": 4001})
	dataDir := t.TempDir()

	info, err := Lookup(configDir, dataDir, "dave", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 10013 {
		t.Errorf("GID = %d, want 10013", info.GID)
	}
	if info.UID != 4001 {
		t.Errorf("UID = %d, want 4001", info.UID)
	}
	if want := filepath.Join(dataDir, "example.com", "users"); info.BasePath != want {
		t.Errorf("BasePath = %q, want %q", info.BasePath, want)
	}
}

// TestLookup_PostmasterIgnoredForGID pins the contract: a stray postmaster file
// (the retired gid source) does NOT override the authoritative gid.toml. This
// is exactly the layering that locked out the live mailbox.
func TestLookup_PostmasterIgnoredForGID(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "", 5000, map[string]uint32{"carol": 3001})

	// A leftover postmaster file claiming a different gid must be ignored.
	postmaster := "postmaster@example.com:9000:6000:/var/mail/example.com\n"
	if err := os.WriteFile(filepath.Join(configDir, "postmaster"), []byte(postmaster), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Lookup(configDir, "", "carol", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 5000 {
		t.Errorf("GID = %d, want 5000 from gid.toml (postmaster 6000 must be ignored)", info.GID)
	}
}

// TestLookup_ConfigGIDIgnored pins that a stray top-level gid in the per-domain
// config.toml does not influence the resolved gid -- identity comes only from
// gid.toml.
func TestLookup_ConfigGIDIgnored(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "gid = 9999\n", 5000, map[string]uint32{"erin": 3501})
	info, err := Lookup(configDir, "", "erin", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 5000 {
		t.Errorf("GID = %d, want 5000 from gid.toml (config.toml gid=9999 must be ignored)", info.GID)
	}
}
