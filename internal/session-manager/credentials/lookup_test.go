package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookup_ValidUser(t *testing.T) {
	// Set up a temporary domain directory with config.toml and passwd file.
	domainsDir := t.TempDir()
	domainDir := filepath.Join(domainsDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write domain config.
	configContent := `gid = 5000

[msgstore]
base_path = "users"
type = "maildir"

[auth]
credential_backend = "passwd"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Write passwd file with a test user. Format: user:hash:mailbox:uid
	passwdContent := "alice:$argon2id$v=19$m=65536,t=3,p=4$salt$hash:alice@example.com:1001\n"
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwdContent), 0600); err != nil {
		t.Fatal(err)
	}

	info, err := Lookup(domainsDir, "", "alice", "example.com")
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
	expectedBase := filepath.Join(domainDir, "users")
	if info.BasePath != expectedBase {
		t.Errorf("BasePath = %q, want %q", info.BasePath, expectedBase)
	}
}

func TestLookup_MissingUser(t *testing.T) {
	domainsDir := t.TempDir()
	domainDir := filepath.Join(domainsDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write empty passwd file.
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Lookup(domainsDir, "", "nonexistent", "example.com")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestLookup_Defaults(t *testing.T) {
	// Test that defaults are applied when config.toml is missing.
	domainsDir := t.TempDir()
	domainDir := filepath.Join(domainsDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}

	// No config.toml — defaults should be used (gid=0, type=maildir, base=users).
	passwdContent := "bob:$argon2id$v=19$m=65536,t=3,p=4$salt$hash:bob@example.com:2001\n"
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwdContent), 0600); err != nil {
		t.Fatal(err)
	}

	info, err := Lookup(domainsDir, "", "bob", "example.com")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}

	if info.UID != 2001 {
		t.Errorf("UID = %d, want 2001", info.UID)
	}
	if info.GID != 0 {
		t.Errorf("GID = %d, want 0 (default)", info.GID)
	}
	if info.StoreType != "maildir" {
		t.Errorf("StoreType = %q, want %q", info.StoreType, "maildir")
	}
}
