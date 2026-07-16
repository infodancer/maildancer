package admin

import (
	"os"
	"path/filepath"
	"strings"
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

// TestFixDomain_CreatesModesAndIsIdempotent checks the doctor sets dir
// modes (chown is root-only and skipped off-root) and runs clean twice.
func TestFixDomain_CreatesModesAndIsIdempotent(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	report, err := p.FixDomain("example.com")
	if err != nil {
		t.Fatalf("FixDomain: %v", err)
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
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain second run: %v", err)
	}
}

// TestConfigPermPlan encodes the config-tree side of the security model:
// everything webadmin-owned with the cfgread group, dirs 2750 (setgid), files
// 0640, so the nonroot
// auth-oidc reader gets group read while root keeps sole write. Regression for
// the outage where root provisioning writes left the tree unreadable to the
// IdP (issue #145).
func TestConfigPermPlan(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	domainDir := filepath.Join(p.Config, "example.com")
	wantDirs := []string{p.Config, domainDir, filepath.Join(domainDir, "keys")}
	wantFiles := []string{
		filepath.Join(p.Config, "gid.toml"),
		filepath.Join(domainDir, "config.toml"),
		filepath.Join(domainDir, "passwd"),
		filepath.Join(domainDir, "uid.toml"),
	}

	got := map[string]permEntry{}
	for _, e := range p.configPermPlan("example.com") {
		got[e.Path] = e
	}

	for _, d := range wantDirs {
		e, ok := got[d]
		if !ok {
			t.Errorf("plan missing dir %s", d)
			continue
		}
		if e.Mode != os.FileMode(0o750)|os.ModeSetgid {
			t.Errorf("%s mode = %v, want 2750 setgid", d, e.Mode)
		}
		if e.UID != int(WebadminUID) || e.GID != int(CfgreadGID) {
			t.Errorf("%s owner = %d:%d, want %d:%d", d, e.UID, e.GID, WebadminUID, CfgreadGID)
		}
	}
	for _, f := range wantFiles {
		e, ok := got[f]
		if !ok {
			t.Errorf("plan missing file %s", f)
			continue
		}
		if e.Mode != os.FileMode(0o640) {
			t.Errorf("%s mode = %v, want 0640", f, e.Mode)
		}
		if e.UID != int(WebadminUID) || e.GID != int(CfgreadGID) {
			t.Errorf("%s owner = %d:%d, want %d:%d", f, e.UID, e.GID, WebadminUID, CfgreadGID)
		}
	}

	// The doctor repairs ownership; it must not invent files the domain
	// doesn't have.
	if _, ok := got[filepath.Join(domainDir, "forwards")]; ok {
		t.Error("plan includes a forwards file that does not exist")
	}

	// Once the file exists, it joins the plan.
	if err := os.WriteFile(filepath.Join(domainDir, "forwards"), []byte("# forwards\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range p.configPermPlan("example.com") {
		if e.Path == filepath.Join(domainDir, "forwards") {
			found = true
			if e.Mode != os.FileMode(0o640) || e.UID != int(WebadminUID) || e.GID != int(CfgreadGID) {
				t.Errorf("forwards entry = %d:%d %v, want %d:%d 0640", e.UID, e.GID, e.Mode, WebadminUID, CfgreadGID)
			}
		}
	}
	if !found {
		t.Error("plan missing forwards file after creation")
	}
}

// TestConfigPermPlan_KeyFiles: files inside keys/ (legacy flat key dir,
// auth-oidc's read-fallback) are planned 0640 webadmin:cfgread.
func TestConfigPermPlan_KeyFiles(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(p.Config, "example.com", "keys", "alice.pub")
	if err := os.WriteFile(keyFile, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, e := range p.configPermPlan("example.com") {
		if e.Path == keyFile {
			if e.Mode != os.FileMode(0o640) || e.UID != int(WebadminUID) || e.GID != int(CfgreadGID) {
				t.Errorf("key file entry = %d:%d %v, want %d:%d 0640", e.UID, e.GID, e.Mode, WebadminUID, CfgreadGID)
			}
			return
		}
	}
	t.Errorf("plan missing key file %s", keyFile)
}

// TestFixDomain_NormalizesConfigTreeModes: the doctor repairs drifted
// config-tree modes (the production trees had 0750 config.toml files) and
// stamps setgid on the config dirs so later root writes inherit the group.
func TestFixDomain_NormalizesConfigTreeModes(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chmod(configToml, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	info, err := os.Stat(configToml)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("config.toml mode = %v, want 0640", info.Mode())
	}
	dirInfo, err := os.Stat(filepath.Join(p.Config, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode()&os.ModeSetgid == 0 {
		t.Errorf("domain config dir missing setgid bit: %v", dirInfo.Mode())
	}
}

// TestCreateDomain_ProvisionsConfigTree: a fresh domain lands with the
// config-tree model already applied (setgid dirs, 0640 files) -- correct at
// creation, no post-hoc repair needed.
func TestCreateDomain_ProvisionsConfigTree(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(filepath.Join(p.Config, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode()&os.ModeSetgid == 0 {
		t.Errorf("domain config dir missing setgid bit: %v", dirInfo.Mode())
	}
	keysInfo, err := os.Stat(filepath.Join(p.Config, "example.com", "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if keysInfo.Mode()&os.ModeSetgid == 0 {
		t.Errorf("keys dir missing setgid bit: %v", keysInfo.Mode())
	}
}

// TestCheckDomain_CleanAfterFix: right after FixDomain the read-only checker
// reports zero drift. Off-root, ownership is not compared (mirroring
// applyPlan's chown skip), so every entry is marked Skipped -- mode drift is
// still what the off-root doctor can fix, and that is what the check covers.
func TestCheckDomain_CleanAfterFix(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	report, err := p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain: %v", err)
	}
	if report.Domain != "example.com" {
		t.Errorf("report domain = %q", report.Domain)
	}
	if n := report.DriftCount(); n != 0 {
		for _, e := range report.Entries {
			if e.Changed {
				t.Logf("drifted: %s want %d:%d %v got %d:%d %v err=%q",
					e.Path, e.UID, e.GID, e.Mode, e.GotUID, e.GotGID, e.GotMode, e.Err)
			}
		}
		t.Errorf("DriftCount = %d after FixDomain, want 0", n)
	}
	if len(report.Entries) < 5 {
		t.Errorf("expected at least 5 entries (data, users, alice, config root, domain config), got %d", len(report.Entries))
	}
	if os.Geteuid() != 0 {
		for _, e := range report.Entries {
			if !e.Skipped {
				t.Errorf("off-root, ownership comparison must be skipped: %s", e.Path)
			}
		}
	}
}

// TestCheckDomain_ModeDrift: a chmod'd config.toml is reported as exactly one
// drifted entry, with the observed mode; restoring the mode makes the check
// clean again. The check itself must not repair anything.
func TestCheckDomain_ModeDrift(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chmod(configToml, 0o750); err != nil {
		t.Fatal(err)
	}

	report, err := p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain: %v", err)
	}
	if n := report.DriftCount(); n != 1 {
		t.Fatalf("DriftCount = %d, want exactly 1", n)
	}
	var drifted *PermResult
	for i := range report.Entries {
		if report.Entries[i].Changed {
			drifted = &report.Entries[i]
		}
	}
	if drifted == nil || drifted.Path != configToml {
		t.Fatalf("drifted entry = %+v, want %s", drifted, configToml)
	}
	if drifted.GotMode.Perm() != 0o750 {
		t.Errorf("GotMode = %v, want 0750", drifted.GotMode)
	}
	if drifted.Mode.Perm() != 0o640 {
		t.Errorf("want mode = %v, want 0640", drifted.Mode)
	}

	// CheckDomain is read-only: the drift is still there.
	info, err := os.Stat(configToml)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("CheckDomain repaired the mode: %v", info.Mode())
	}

	// Restore and the check runs clean.
	if err := os.Chmod(configToml, 0o640); err != nil {
		t.Fatal(err)
	}
	report, err = p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain after restore: %v", err)
	}
	if n := report.DriftCount(); n != 0 {
		t.Errorf("DriftCount after restore = %d, want 0", n)
	}
}

// TestCheckDomain_NoGIDIsFindingNotError: a domain with no allocated gid is a
// drift finding, not an error that aborts the check -- and the check must not
// allocate one (that is FixDomain's job).
func TestCheckDomain_NoGIDIsFindingNotError(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.Config, "gid.toml")); err != nil {
		t.Fatal(err)
	}

	report, err := p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain must not fail on a missing gid: %v", err)
	}
	found := false
	for _, e := range report.Entries {
		if e.Changed && strings.Contains(e.Err, "gid") {
			found = true
		}
	}
	if !found {
		t.Error("expected a drift finding about the missing gid")
	}
	if report.DriftCount() == 0 {
		t.Error("missing gid must count as drift")
	}

	// Strictly read-only: no gid was allocated.
	if _, err := p.domainGid("example.com"); err == nil {
		t.Error("CheckDomain allocated a gid; it must not write")
	}
}

// TestCheckDomain_MissingDirIsDriftNotCreated: a data directory the model says
// should exist is reported as drift, and the check does not create it.
func TestCheckDomain_MissingDirIsDriftNotCreated(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	aliceDir := filepath.Join(p.Data, "example.com", "users", "alice")
	if err := os.RemoveAll(aliceDir); err != nil {
		t.Fatal(err)
	}

	report, err := p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain: %v", err)
	}
	if n := report.DriftCount(); n != 1 {
		t.Fatalf("DriftCount = %d, want 1 (missing user dir)", n)
	}
	for _, e := range report.Entries {
		if e.Changed && e.Path != aliceDir {
			t.Errorf("unexpected drifted entry %s", e.Path)
		}
	}
	if _, err := os.Stat(aliceDir); !os.IsNotExist(err) {
		t.Errorf("CheckDomain created the missing dir (stat err=%v); it must not write", err)
	}
}

// TestFixDomain_AllocatesMissingGID is the regression for the homelab failure:
// fix-perms errored on a domain whose data-tree config.toml had no gid. FixDomain
// now allocates the missing gid (and any missing uids) before applying perms,
// so it succeeds and reports the allocation.
func TestFixDomain_AllocatesMissingGID(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	// Simulate a domain with no allocated gid by dropping the gid.toml entry.
	// (The test data dir's group is the test user's, below the allocator floor,
	// so adoptDomainGID skips it and FixDomain allocates a fresh gid.)
	if err := os.Remove(filepath.Join(p.Config, "gid.toml")); err != nil {
		t.Fatal(err)
	}

	report, err := p.FixDomain("example.com")
	if err != nil {
		t.Fatalf("FixDomain must allocate the missing gid, got: %v", err)
	}
	if len(report.Allocated) == 0 {
		t.Errorf("expected an allocation to be reported, got none")
	}

	// The gid is now persisted in the authoritative gid.toml.
	gid, err := p.domainGid("example.com")
	if err != nil || gid == 0 {
		t.Errorf("gid not allocated: gid=%d err=%v", gid, err)
	}
}

// TestMutationsRepairConfigOwnership: user mutations rewrite config-tree
// files via temp+rename, so a root-run userctl would otherwise leave
// root-owned inodes webadmin cannot append to (#152). Every mutating entry
// point re-applies the config plan; off-root that at least repairs modes,
// which is what this asserts (the ownership half is covered by the
// rootintegration suite).
func TestMutationsRepairConfigOwnership(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	// Drift a file the mutation does NOT rewrite: the passwd rewrite itself
	// recreates passwd at 0640, so only a sibling file proves the plan-wide
	// repair actually ran.
	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chmod(configToml, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := p.ResetPassword("example.com", "alice", "newpassword456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	info, err := os.Stat(configToml)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("config.toml mode after mutation = %v, want 0640 (repair hook must run)", info.Mode())
	}
}
