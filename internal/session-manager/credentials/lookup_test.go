package credentials

import (
	"fmt"
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
	configDir, domainDir := setupDomain(t, "example.com", cfg, 10014, map[string]uint32{"alice": 10025})

	info, err := Lookup(configDir, "", "alice", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.UID != 10025 {
		t.Errorf("UID = %d, want 10025", info.UID)
	}
	if info.GID != 10014 {
		t.Errorf("GID = %d, want 10014", info.GID)
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
	configDir, _ := setupDomain(t, "example.com", "", 10014, nil)
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
	if err := m.SetUserUID("example.com", "bob", 10035); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(configDir, "", "bob", "example.com"); err == nil {
		t.Fatal("expected hard error for domain with no gid allocation")
	}
}

// TestLookup_DataPath: a relative base_path resolves against the data tree, not
// the config tree, when domainsDataPath is set.
func TestLookup_DataPath(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "", 10013, map[string]uint32{"dave": 10028})
	dataDir := t.TempDir()

	info, err := Lookup(configDir, dataDir, "dave", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 10013 {
		t.Errorf("GID = %d, want 10013", info.GID)
	}
	if info.UID != 10028 {
		t.Errorf("UID = %d, want 10028", info.UID)
	}
	if want := filepath.Join(dataDir, "example.com", "users"); info.BasePath != want {
		t.Errorf("BasePath = %q, want %q", info.BasePath, want)
	}
}

// TestLookup_PostmasterIgnoredForGID pins the contract: a stray postmaster file
// (the retired gid source) does NOT override the authoritative gid.toml. This
// is exactly the layering that locked out the live mailbox.
func TestLookup_PostmasterIgnoredForGID(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "", 10014, map[string]uint32{"carol": 10026})

	// A leftover postmaster file claiming a different gid must be ignored.
	postmaster := "postmaster@example.com:9000:6000:/var/mail/example.com\n"
	if err := os.WriteFile(filepath.Join(configDir, "postmaster"), []byte(postmaster), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Lookup(configDir, "", "carol", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 10014 {
		t.Errorf("GID = %d, want 10014 from gid.toml (postmaster 6000 must be ignored)", info.GID)
	}
}

// TestLookup_ConfigGIDIgnored pins that a stray top-level gid in the per-domain
// config.toml does not influence the resolved gid -- identity comes only from
// gid.toml.
func TestLookup_ConfigGIDIgnored(t *testing.T) {
	configDir, _ := setupDomain(t, "example.com", "gid = 9999\n", 10014, map[string]uint32{"erin": 10027})
	info, err := Lookup(configDir, "", "erin", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if info.GID != 10014 {
		t.Errorf("GID = %d, want 10014 from gid.toml (config.toml gid=9999 must be ignored)", info.GID)
	}
}

// writeRawIdentityMaps writes gid.toml/uid.toml directly, bypassing the
// identity Manager's validation -- simulating a corrupted or hand-edited map.
func writeRawIdentityMaps(t *testing.T, domainName string, gid, uid uint32) (configDir string) {
	t.Helper()
	configDir = t.TempDir()
	domainDir := filepath.Join(configDir, domainName)
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gidMap := fmt.Sprintf("%q = %d\n", domainName, gid)
	if err := os.WriteFile(filepath.Join(configDir, "gid.toml"), []byte(gidMap), 0o644); err != nil {
		t.Fatal(err)
	}
	uidMap := fmt.Sprintf("%q = %d\n", "mallory", uid)
	if err := os.WriteFile(filepath.Join(domainDir, "uid.toml"), []byte(uidMap), 0o644); err != nil {
		t.Fatal(err)
	}
	return configDir
}

// TestLookup_RefusesUnallocatableIDs: the identity maps are the trust boundary
// for spawn credentials. Entries outside the allocatable range -- root, a
// service account, or the excluded 65532-65535 band -- must be refused, never
// handed to SysProcAttr.Credential.
func TestLookup_RefusesUnallocatableIDs(t *testing.T) {
	tests := []struct {
		name     string
		gid, uid uint32
	}{
		{"uid zero spawns root", 10014, 0},
		{"gid zero spawns root group", 0, 10025},
		{"uid is a service account", 10014, 903},
		{"gid is a service group", 900, 10025},
		{"uid is distroless nonroot", 10014, 65532},
		{"gid is nobody band", 65533, 10025},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configDir := writeRawIdentityMaps(t, "example.com", tt.gid, tt.uid)
			if _, err := Lookup(configDir, "", "mallory", "example.com"); err == nil {
				t.Fatalf("Lookup accepted gid=%d uid=%d; want refusal", tt.gid, tt.uid)
			}
		})
	}
}
