package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDomainPermPlan checks the plan encodes the security model: shared dirs
// root:{gid} 2750 (setgid), each user dir uid:gid 0700. The gid is resolved
// from the data-tree config.toml -- the bug that made fix-domain-perms.sh skip
// split-tree domains was reading it from the config tree.
func TestDomainPermPlan(t *testing.T) {
	p := newTestPaths(t)
	gid, err := p.CreateDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	plan, err := p.domainPermPlan("example.com")
	if err != nil {
		t.Fatalf("domainPermPlan: %v", err)
	}

	dataDir := filepath.Join(p.Data, "example.com")
	usersDir := filepath.Join(dataDir, "users")
	aliceDir := filepath.Join(usersDir, "alice")

	want := map[string]permEntry{
		dataDir:  {Path: dataDir, UID: 0, GID: int(gid), Mode: os.FileMode(0o750) | os.ModeSetgid},
		usersDir: {Path: usersDir, UID: 0, GID: int(gid), Mode: os.FileMode(0o750) | os.ModeSetgid},
		aliceDir: {Path: aliceDir, UID: -1, GID: int(gid), Mode: os.FileMode(0o700)}, // UID checked below
	}

	got := map[string]permEntry{}
	for _, e := range plan {
		got[e.Path] = e
	}

	for path, w := range want {
		g, ok := got[path]
		if !ok {
			t.Errorf("plan missing %s", path)
			continue
		}
		if g.Mode != w.Mode {
			t.Errorf("%s mode = %v, want %v", path, g.Mode, w.Mode)
		}
		if g.GID != w.GID {
			t.Errorf("%s gid = %d, want %d", path, g.GID, w.GID)
		}
	}
	// Shared dirs are root-owned.
	if got[dataDir].UID != 0 || got[usersDir].UID != 0 {
		t.Errorf("shared dirs must be root-owned, got domain=%d users=%d", got[dataDir].UID, got[usersDir].UID)
	}
	// The user dir is owned by alice's allocated uid.
	if a, ok := got[aliceDir]; !ok || a.UID < 10000 {
		t.Errorf("alice dir uid = %d (ok=%v), want her allocated uid >= 10000", a.UID, ok)
	}
}

// TestDomainPermPlan_NoGID fails clearly for a domain without an allocated gid
// rather than silently skipping it (the fix-domain-perms.sh failure mode).
func TestDomainPermPlan_NoGID(t *testing.T) {
	p := newTestPaths(t)
	// A data dir with no gid in config.toml.
	if err := os.MkdirAll(filepath.Join(p.Data, "nogid.example"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Data, "nogid.example", "config.toml"), []byte("[domain]\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := p.domainPermPlan("nogid.example"); err == nil {
		t.Fatal("expected an error for a domain with no gid, got nil")
	}
}

// TestFixDomainPerms_CreatesModesAndIsIdempotent checks the doctor sets dir
// modes (chown is root-only and skipped off-root) and runs clean twice.
func TestFixDomainPerms_CreatesModesAndIsIdempotent(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	report, err := p.FixDomainPerms("example.com")
	if err != nil {
		t.Fatalf("FixDomainPerms: %v", err)
	}
	if report.Domain != "example.com" {
		t.Errorf("report domain = %q", report.Domain)
	}
	if len(report.Entries) < 3 {
		t.Errorf("expected at least 3 entries (domain, users, alice), got %d", len(report.Entries))
	}

	// Setgid mode landed on the shared dirs (chmod works off-root for own dirs).
	info, err := os.Stat(filepath.Join(p.Data, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf("domain dir missing setgid bit: %v", info.Mode())
	}

	// Idempotent: a second run also succeeds.
	if _, err := p.FixDomainPerms("example.com"); err != nil {
		t.Fatalf("FixDomainPerms second run: %v", err)
	}
}
