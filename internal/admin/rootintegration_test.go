//go:build rootintegration

package admin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/infodancer/maildancer/auth/identity"
)

// This file is the root-context integration test for the permission model in
// perms.go. Every other test in this package runs off-root, where applyPlan
// skips the chown path -- so the model's actual enforcement (who can and
// cannot read what) never executes under test. This test runs as root (in a
// container: `task test:root`), applies the model for real, and probes it
// from the uids the model is about.
//
// The nonroot reader contract being pinned:
//   - uid 65532 (authReadGID, any gid with 65532 as the primary works via the
//     group bits) must be able to read {config}/{domain}/config.toml and
//     passwd after FixDomain -- that is auth-oidc's read path.
//   - a mail user (uid >= 10000, including the domain's own uid:gid pair)
//     must get permission denied on the config tree. That denial is
//     deliberate design: mail-session degrades to defaults (see
//     auth/domain/filesystem.go). Do NOT "fix" it.
//   - the same mail user must be able to read files in its own data-tree
//     directory ({data}/{domain}/users/{user}, uid:gid 0700).

// probeEnvVar switches the test binary into probe mode: the process reads the
// named path and exits 0 on success, 3 on permission denied, 4 on any other
// error, without running tests. The test re-execs itself under a different
// uid/gid to check the model from that identity's point of view.
const probeEnvVar = "ROOTTEST_PROBE_PATH"

// Probe exit codes.
const (
	probeOK     = 0
	probeDenied = 3
	probeErr    = 4
)

func TestMain(m *testing.M) {
	if path := os.Getenv(probeEnvVar); path != "" {
		_, err := os.ReadFile(path)
		switch {
		case err == nil:
			os.Exit(probeOK)
		case os.IsPermission(err):
			os.Exit(probeDenied)
		default:
			fmt.Fprintf(os.Stderr, "probe %s: %v\n", path, err)
			os.Exit(probeErr)
		}
	}
	os.Exit(m.Run())
}

// probeRead re-execs the test binary as uid:gid and returns the probe exit
// code for reading path. Supplementary groups are dropped (Credential.Groups
// nil => setgroups to empty), so the probe holds exactly the identity given.
func probeRead(t *testing.T, bin string, uid, gid uint32, path string) int {
	t.Helper()
	cmd := exec.Command(bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), probeEnvVar+"="+path)
	cmd.Dir = "/" // the probe uid may not be able to enter our cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return probeOK
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code := ee.ExitCode()
		if code == probeErr {
			t.Logf("probe uid=%d gid=%d %s: unexpected error: %s", uid, gid, path, out)
		}
		return code
	}
	t.Fatalf("probe uid=%d gid=%d %s: exec failed: %v (%s)", uid, gid, path, err, out)
	return -1
}

// copyProbeBinary copies the running test binary somewhere the probe uids can
// execute it: `go test` leaves the binary under a 0700 root-owned build dir,
// unreachable once we drop privileges.
func copyProbeBinary(t *testing.T, dir string) string {
	t.Helper()
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatalf("open test binary: %v", err)
	}
	defer src.Close()
	bin := filepath.Join(dir, "probe.test")
	dst, err := os.OpenFile(bin, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestRootPermissionModel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; run via 'task test:root' (containerized)")
	}

	// t.TempDir() and its parent are 0700 when created by root; probe uids
	// need execute (traverse) on the whole chain. /tmp itself is 1777, so
	// opening up the two dirs t.TempDir created is enough.
	base := t.TempDir()
	for _, d := range []string{base, filepath.Dir(base)} {
		if err := os.Chmod(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}

	// Mirror newTestPaths (admin_test.go), but the data root gets 0711: it is
	// not part of the model's plan (in production it is a mount point), and
	// mail users must be able to traverse it to reach the per-domain dirs
	// where the model's group bits take over. The config root IS part of the
	// plan (configPermPlan) and gets fixed to root:authReadGID 2750 below.
	p := Paths{
		Config: filepath.Join(base, "config"),
		Data:   filepath.Join(base, "data"),
	}
	if err := os.MkdirAll(p.Config, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Data, 0o711); err != nil {
		t.Fatal(err)
	}

	bin := copyProbeBinary(t, base)

	createdGid, err := p.CreateDomain("example.com")
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// As root, FixDomain must apply the full model: no skipped chowns, no
	// per-path errors. This is the enforcement path no off-root test reaches.
	report, err := p.FixDomain("example.com")
	if err != nil {
		t.Fatalf("FixDomain: %v", err)
	}
	if len(report.Entries) == 0 {
		t.Fatal("FixDomain returned no entries")
	}
	for _, e := range report.Entries {
		if e.Skipped {
			t.Errorf("entry skipped under root: %s", e.Path)
		}
		if e.Err != "" {
			t.Errorf("entry error: %s: %s", e.Path, e.Err)
		}
	}

	// Resolve the identities the probes run as from the authoritative maps.
	domainGid, err := identity.DomainGID(p.Config, "example.com")
	if err != nil {
		t.Fatalf("DomainGID: %v", err)
	}
	if domainGid != createdGid {
		t.Fatalf("gid mismatch: CreateDomain=%d identity=%d", createdGid, domainGid)
	}
	aliceUID, err := identity.UserUID(p.Config, "example.com", "alice")
	if err != nil {
		t.Fatalf("UserUID: %v", err)
	}

	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	passwdFile := filepath.Join(p.Config, "example.com", "passwd")

	// Positive first: the authReadGID reader (auth-oidc's distroless nonroot
	// identity) can read the domain config and passwd. This also proves the
	// tempdir chain is traversable, so the denials below fail for the right
	// reason (config-tree perms), not a broken test setup.
	if code := probeRead(t, bin, authReadGID, authReadGID, configToml); code != probeOK {
		t.Errorf("uid %d read %s: exit %d, want %d (auth-oidc must read domain config)", authReadGID, configToml, code, probeOK)
	}
	if code := probeRead(t, bin, authReadGID, authReadGID, passwdFile); code != probeOK {
		t.Errorf("uid %d read %s: exit %d, want %d (auth-oidc must read passwd)", authReadGID, passwdFile, code, probeOK)
	}

	// The mail user -- even holding the domain's own gid -- is denied on the
	// config tree. Deliberate: mail-session degrades to defaults. Pinned so
	// nobody "fixes" the denial.
	if code := probeRead(t, bin, aliceUID, domainGid, configToml); code != probeDenied {
		t.Errorf("mail user %d:%d read %s: exit %d, want %d (config tree must deny mail users)", aliceUID, domainGid, configToml, code, probeDenied)
	}
	// An unrelated uid:gid is denied too.
	if code := probeRead(t, bin, 20000, 20000, configToml); code != probeDenied {
		t.Errorf("unrelated 20000:20000 read %s: exit %d, want %d", configToml, code, probeDenied)
	}

	// The positive side of the data model: the same mail user reads a file in
	// its own {data}/{domain}/users/{user} dir (uid:gid 0700 after FixDomain).
	aliceDir := filepath.Join(p.Data, "example.com", "users", "alice")
	mailFile := filepath.Join(aliceDir, "roottest-mail")
	if err := os.WriteFile(mailFile, []byte("mail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(mailFile, int(aliceUID), int(domainGid)); err != nil {
		t.Fatal(err)
	}
	if code := probeRead(t, bin, aliceUID, domainGid, mailFile); code != probeOK {
		t.Errorf("mail user %d:%d read own data file %s: exit %d, want %d", aliceUID, domainGid, mailFile, code, probeOK)
	}
}

// TestRootCheckDomainDrift pins CheckDomain's root-context contract: as root,
// ownership IS compared (no Skipped entries), so a chown-to-root of a config
// file -- the exact drift class behind the production outage -- shows up as
// drift, and a re-run of FixDomain makes the check clean again. Off-root
// tests can only cover the mode side of this.
func TestRootCheckDomainDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; run via 'task test:root' (containerized)")
	}

	base := t.TempDir()
	p := Paths{
		Config: filepath.Join(base, "config"),
		Data:   filepath.Join(base, "data"),
	}
	if err := os.MkdirAll(p.Config, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Data, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	// Clean right after a root FixDomain -- and nothing skipped, because root
	// compares ownership as well as modes.
	report, err := p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain: %v", err)
	}
	if n := report.DriftCount(); n != 0 {
		for _, e := range report.Entries {
			if e.Changed {
				t.Logf("drifted: %s want %d:%d %v got %d:%d %v err=%q",
					e.Path, e.UID, e.GID, e.Mode, e.GotUID, e.GotGID, e.GotMode, e.Err)
			}
		}
		t.Fatalf("DriftCount = %d after root FixDomain, want 0", n)
	}
	for _, e := range report.Entries {
		if e.Skipped {
			t.Errorf("entry skipped under root: %s", e.Path)
		}
	}

	// Chown a config file to root:root -- losing the authReadGID group that
	// lets auth-oidc read it. This is ownership-only drift (mode untouched),
	// invisible to an off-root check.
	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chown(configToml, 0, 0); err != nil {
		t.Fatal(err)
	}
	report, err = p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain after chown: %v", err)
	}
	if n := report.DriftCount(); n != 1 {
		t.Fatalf("DriftCount = %d after chown-to-root, want exactly 1", n)
	}
	for _, e := range report.Entries {
		if !e.Changed {
			continue
		}
		if e.Path != configToml {
			t.Errorf("unexpected drifted entry %s", e.Path)
		}
		if e.GotGID != 0 || e.GID != authReadGID {
			t.Errorf("drift entry gid = got %d want-field %d; expected got 0, want %d", e.GotGID, e.GID, authReadGID)
		}
	}

	// FixDomain repairs it; the check runs clean again.
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain (repair): %v", err)
	}
	report, err = p.CheckDomain("example.com")
	if err != nil {
		t.Fatalf("CheckDomain after repair: %v", err)
	}
	if n := report.DriftCount(); n != 0 {
		t.Errorf("DriftCount = %d after repair, want 0", n)
	}
}
