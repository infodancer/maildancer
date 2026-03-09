package domain

import (
	"os"
	"path/filepath"
	"testing"
)

const postmasterContent = `# System postmaster
postmaster:10001:10001:/var/mail

# Domain postmasters
postmaster@matthewjayhunter.com:10013:10014:/opt/infodancer/domains/matthewjayhunter.com
postmaster@AMYHUNTER.ORG:10015:10016:/opt/infodancer/domains/amyhunter.org
`

func TestParsePostmasterFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postmaster")
	if err := os.WriteFile(path, []byte(postmasterContent), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := ParsePostmasterFile(path)
	if err != nil {
		t.Fatalf("ParsePostmasterFile: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	sys := entries[""]
	if sys == nil {
		t.Fatal("system postmaster entry missing")
	}
	if sys.UID != 10001 || sys.GID != 10001 || sys.DataPath != "/var/mail" {
		t.Errorf("system: got uid=%d gid=%d path=%q", sys.UID, sys.GID, sys.DataPath)
	}

	mjh := entries["matthewjayhunter.com"]
	if mjh == nil {
		t.Fatal("matthewjayhunter.com entry missing")
	}
	if mjh.UID != 10013 || mjh.GID != 10014 || mjh.DataPath != "/opt/infodancer/domains/matthewjayhunter.com" {
		t.Errorf("matthewjayhunter.com: got uid=%d gid=%d path=%q", mjh.UID, mjh.GID, mjh.DataPath)
	}

	// Domain name must be lowercased.
	amy := entries["amyhunter.org"]
	if amy == nil {
		t.Fatal("amyhunter.org entry missing (should be lowercased from AMYHUNTER.ORG)")
	}
	if amy.GID != 10016 {
		t.Errorf("amyhunter.org: expected gid 10016, got %d", amy.GID)
	}
}

func TestParsePostmasterFile_Missing(t *testing.T) {
	_, err := ParsePostmasterFile("/nonexistent/postmaster")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestParsePostmasterFile_BadFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postmaster")
	if err := os.WriteFile(path, []byte("postmaster:10001:10001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ParsePostmasterFile(path)
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
}

func TestLookupDomainPostmaster(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "postmaster"), []byte(postmasterContent), 0o644); err != nil {
		t.Fatal(err)
	}

	entry := LookupDomainPostmaster(dir, "matthewjayhunter.com")
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.GID != 10014 {
		t.Errorf("expected GID 10014, got %d", entry.GID)
	}

	// Missing domain returns nil without error.
	if got := LookupDomainPostmaster(dir, "unknown.example"); got != nil {
		t.Errorf("expected nil for unknown domain, got %+v", got)
	}

	// Missing file returns nil without error.
	if got := LookupDomainPostmaster("/nonexistent", "example.com"); got != nil {
		t.Errorf("expected nil for missing file, got %+v", got)
	}
}
