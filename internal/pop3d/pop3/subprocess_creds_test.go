package pop3

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookupCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Domain config with gid and explicit paths.
	configContent := `gid = 2001

[auth]
type = "passwd"
credential_backend = "passwd"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Passwd file with uid in field 4.
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("testuser:HASH:testuser:1001\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	s := &SubprocessServer{domainsPath: tmpDir}

	uid, gid, basePath, err := s.lookupCredentials("testuser@example.com")
	if err != nil {
		t.Fatalf("lookupCredentials: %v", err)
	}
	if uid != 1001 {
		t.Errorf("expected uid 1001, got %d", uid)
	}
	if gid != 2001 {
		t.Errorf("expected gid 2001, got %d", gid)
	}
	expected := filepath.Join(domainDir, "users")
	if basePath != expected {
		t.Errorf("expected basePath %q, got %q", expected, basePath)
	}
}

func TestLookupCredentials_NoConfig(t *testing.T) {
	// When config.toml is absent, defaults apply (gid=0, backend="passwd", basepath="users").
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "noconfig.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("alice:HASH:alice:500\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	s := &SubprocessServer{domainsPath: tmpDir}

	uid, gid, basePath, err := s.lookupCredentials("alice@noconfig.com")
	if err != nil {
		t.Fatalf("lookupCredentials: %v", err)
	}
	if uid != 500 {
		t.Errorf("expected uid 500, got %d", uid)
	}
	if gid != 0 {
		t.Errorf("expected gid 0 (not configured), got %d", gid)
	}
	expected := filepath.Join(domainDir, "users")
	if basePath != expected {
		t.Errorf("expected basePath %q, got %q", expected, basePath)
	}
}

func TestLookupCredentials_MissingUser(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("other:HASH:other:1002\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	s := &SubprocessServer{domainsPath: tmpDir}

	_, _, _, err := s.lookupCredentials("nobody@example.com")
	if err == nil {
		t.Error("expected error for missing user, got nil")
	}
}

func TestLookupCredentials_InvalidUsername(t *testing.T) {
	s := &SubprocessServer{domainsPath: "/tmp"}
	_, _, _, err := s.lookupCredentials("nodomain")
	if err == nil {
		t.Error("expected error for username without @, got nil")
	}
}
