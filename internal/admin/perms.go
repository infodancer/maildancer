package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/infodancer/maildancer/auth/identity"
	"github.com/infodancer/maildancer/auth/passwd"
)

// This file encodes the mail privilege-separation directory model
// (infodancer docs/mail-security-model.md) and applies it at provisioning time
// -- not via a post-hoc repair script. The model for the writable data tree:
//
//	data/{domain}/             root:{gid}   2750  (drwxr-s---)
//	data/{domain}/users/       root:{gid}   2750
//	data/{domain}/users/{user} {uid}:{gid}  0700  (drwx------)
//
// The shared domain and users directories are root-owned so no single mail user
// can alter the structure, but carry the domain gid with setgid + group-execute
// so member uids (the recipients) can traverse to reach their own maildir. Each
// user directory is owned by that user's uid so the privilege-separated
// mail-session, spawned as the recipient, can read and write its own maildir
// and keyring.
//
// The read-only config tree has its own model (issues #145, #152):
//
//	config/                    webadmin:cfgread   2750  (drwxr-s---)
//	config/{domain}/           webadmin:cfgread   2750
//	config/{domain}/*          webadmin:cfgread   0640  (files; subdirs 2750)
//
// webadmin owns the tree because it is the writer -- owning its own writes is
// what lets it eventually run unprivileged (issue #154). The cfgread group
// grants read to auth-oidc (each domain's config.toml and passwd, over a
// read-only mount) and to queue-manager (per-domain outbound routing);
// membership is an explicit grant via a dedicated gid, deliberately NOT the
// distroless-nonroot 65532, so merely running as distroless nonroot conveys
// nothing. mail-session (recipient uid) is deliberately denied and degrades
// to defaults (see auth/domain/filesystem.go). The setgid bit on the
// directories makes every file any writer creates later -- webadmin's
// temp+rename saves, root-run userctl, the id allocator -- inherit the group
// with no cooperation from the write sites; a root-owned file left by a
// root-run userctl is repaired to webadmin ownership by the next fix or
// provisioning pass, and stays group-readable meanwhile.
//
// Ownership changes require root; on a non-root process (dev, tests, rootless)
// applyPlan is a no-op for chown and reports it, since the uid/gid model is only
// meaningful under privilege separation anyway.

// sharedDirMode is the mode for the shared domain and users directories:
// rwxr-s--- with the setgid bit so new entries inherit the domain gid.
const sharedDirMode = os.FileMode(0o750) | os.ModeSetgid

// userDirMode is the mode for a per-user directory: rwx------.
const userDirMode = os.FileMode(0o700)

// rootUID owns the shared domain/users directories.
const rootUID = 0

// configFileMode is the mode for config-tree files: rw-r----- so root writes
// and the IdP group reads; no world bits keeps passwd private to the two.
const configFileMode = os.FileMode(0o640)

// permEntry is one path's desired ownership and mode.
type permEntry struct {
	Path string
	UID  int
	GID  int
	Mode os.FileMode
}

// PermReport records what a permission apply/check did or would do.
type PermReport struct {
	Domain string
	// Allocated lists ids the fix allocated before applying perms, e.g.
	// "example.com gid=10013" or "alice@example.com uid=10025".
	Allocated []string
	// Warnings lists non-fatal configuration problems found during the fix,
	// e.g. a real user whose mail is shadowed by a forward.
	Warnings []string
	Entries  []PermResult
}

// PermResult is the per-path outcome of an apply or a check.
type PermResult struct {
	Path string
	UID  int
	GID  int
	Mode os.FileMode
	// Changed means the apply changed this path -- or, in a CheckDomain
	// report, that the path has drifted from the model.
	Changed bool
	// Skipped means chown was not applied (apply) or ownership was not
	// compared (check) because the process is not root.
	Skipped bool
	Err     string // non-empty when this path could not be fully fixed/checked
	// GotUID, GotGID, and GotMode record the observed owner and mode bits in
	// a CheckDomain report (-1 uid/gid when the path is missing). Apply
	// reports leave them zero.
	GotUID  int
	GotGID  int
	GotMode os.FileMode
}

// domainPermPlan returns the desired ownership/mode for a domain's data tree
// and every user under it, per the security model. The gid is resolved from the
// data-volume config.toml (the authoritative location) -- not the config tree,
// where it does not live. Returns an error if the domain has no gid yet.
func (p Paths) domainPermPlan(domain string) ([]permEntry, error) {
	gid, err := p.domainGid(domain)
	if err != nil {
		return nil, fmt.Errorf("resolve gid: %w", err)
	}

	dataDir := filepath.Join(p.Data, domain)
	usersDir := filepath.Join(dataDir, "users")
	plan := []permEntry{
		{Path: dataDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
		{Path: usersDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
	}

	// Each user gets their own directory owned uid:gid. The uid is the
	// authoritative one from {config}/{domain}/uid.toml; a passwd entry without
	// an allocated uid yet (ErrNoUID) is skipped -- nothing to own.
	users, err := passwd.ListUsers(filepath.Join(p.Config, domain, "passwd"))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		uid, err := identity.UserUID(p.Config, domain, u.Username)
		if errors.Is(err, identity.ErrNoUID) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve uid for %s: %w", u.Username, err)
		}
		plan = append(plan, permEntry{
			Path: filepath.Join(usersDir, u.Username),
			UID:  int(uid),
			GID:  int(gid),
			Mode: userDirMode,
		})
	}
	return plan, nil
}

// configPermPlan returns the desired ownership/mode for a domain's config-tree
// paths, plus the shared config root and its ledger files: everything
// webadmin:cfgread, dirs setgid. File entries are planned only when the file
// exists -- the doctor repairs ownership, it does not invent files.
func (p Paths) configPermPlan(domain string) []permEntry {
	domainDir := filepath.Join(p.Config, domain)
	plan := []permEntry{
		{Path: p.Config, UID: int(WebadminUID), GID: int(CfgreadGID), Mode: sharedDirMode},
		{Path: domainDir, UID: int(WebadminUID), GID: int(CfgreadGID), Mode: sharedDirMode},
	}

	// Shared files at the config root, then the domain's own files.
	for _, f := range []string{
		filepath.Join(p.Config, "gid.toml"),
		filepath.Join(p.Config, "config.toml"),
		filepath.Join(domainDir, "config.toml"),
		filepath.Join(domainDir, "passwd"),
		filepath.Join(domainDir, "uid.toml"),
		filepath.Join(domainDir, "forwards"),
	} {
		if info, err := os.Stat(f); err == nil && info.Mode().IsRegular() {
			plan = append(plan, permEntry{Path: f, UID: int(WebadminUID), GID: int(CfgreadGID), Mode: configFileMode})
		}
	}

	// Optional subdirectories and their files (keys/ is auth-oidc's legacy
	// flat-key read-fallback; user_forwards/ is read by root-side delivery).
	for _, d := range []string{
		filepath.Join(domainDir, "keys"),
		filepath.Join(domainDir, "user_forwards"),
	} {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			continue
		}
		plan = append(plan, permEntry{Path: d, UID: int(WebadminUID), GID: int(CfgreadGID), Mode: sharedDirMode})
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			plan = append(plan, permEntry{Path: filepath.Join(d, e.Name()), UID: int(WebadminUID), GID: int(CfgreadGID), Mode: configFileMode})
		}
	}
	return plan
}

// applyPlan applies a permission plan, creating missing directories. Ownership
// (chown) is applied only when running as root; otherwise the entry is recorded
// as skipped. Modes are always applied (a process can chmod paths it owns).
// Missing paths are created before chown/chmod so a freshly provisioned tree
// lands correct in one pass.
func applyPlan(plan []permEntry, createMissing bool) PermReport {
	root := os.Geteuid() == 0
	report := PermReport{}
	for _, e := range plan {
		res := PermResult{Path: e.Path, UID: e.UID, GID: e.GID, Mode: e.Mode}

		info, statErr := os.Stat(e.Path)
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) {
				res.Err = statErr.Error()
				report.Entries = append(report.Entries, res)
				continue
			}
			if !createMissing {
				res.Skipped = true
				res.Err = "does not exist"
				report.Entries = append(report.Entries, res)
				continue
			}
			if err := os.MkdirAll(e.Path, e.Mode.Perm()); err != nil {
				res.Err = fmt.Sprintf("create: %v", err)
				report.Entries = append(report.Entries, res)
				continue
			}
			res.Changed = true
			info = nil
		}

		// Mode (including setgid): chmod what we own.
		if info == nil || info.Mode() != e.Mode {
			if err := os.Chmod(e.Path, e.Mode); err != nil {
				res.Err = appendErr(res.Err, fmt.Sprintf("chmod: %v", err))
			} else if info != nil {
				res.Changed = true
			}
		}

		// Ownership: requires root.
		if root {
			if err := os.Chown(e.Path, e.UID, e.GID); err != nil {
				res.Err = appendErr(res.Err, fmt.Sprintf("chown %d:%d: %v", e.UID, e.GID, err))
			} else {
				res.Changed = true
			}
		} else {
			res.Skipped = true
		}

		report.Entries = append(report.Entries, res)
	}
	return report
}

func appendErr(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// provisionDomainDataDirs creates and owns a domain's shared data directories
// (domain dir + users dir) per the security model. Called at domain creation.
func (p Paths) provisionDomainDataDirs(domain string) error {
	gid, err := p.domainGid(domain)
	if err != nil {
		return fmt.Errorf("resolve gid: %w", err)
	}
	dataDir := filepath.Join(p.Data, domain)
	usersDir := filepath.Join(dataDir, "users")
	plan := []permEntry{
		{Path: dataDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
		{Path: usersDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
	}
	report := applyPlan(plan, true)
	return report.firstError()
}

// provisionDomainConfigTree applies the config-tree ownership model to a
// freshly created domain (webadmin:cfgread, setgid dirs, 0640 files) so
// auth-oidc can read it from first boot. Ownership is a no-op off-root; modes
// still apply.
func (p Paths) provisionDomainConfigTree(domain string) error {
	report := applyPlan(p.configPermPlan(domain), false)
	return report.firstError()
}

// provisionUserDataDir creates and owns a single user's data directory
// (uid:gid 0700). Called at user creation, before any keyring is written.
func (p Paths) provisionUserDataDir(domain, username string, uid uint32) error {
	gid, err := p.domainGid(domain)
	if err != nil {
		return fmt.Errorf("resolve gid: %w", err)
	}
	plan := []permEntry{{
		Path: p.userKeyringDir(domain, username),
		UID:  int(uid),
		GID:  int(gid),
		Mode: userDirMode,
	}}
	report := applyPlan(plan, true)
	return report.firstError()
}

// FixDomain repairs a domain's data tree against the security model,
// idempotently: it first allocates any missing gid (domain) or uid (passwd
// entries), then applies ownership/modes. It is the supported replacement for
// the standalone fix-domain-perms.sh -- it resolves the gid from the data tree
// (where it lives), allocates ids the perms depend on (so it never fails on an
// unallocated domain), and never silently skips a configured domain. Returns a
// report of ids allocated and every path touched.
func (p Paths) FixDomain(domain string) (PermReport, error) {
	if !ValidDomainName(domain) {
		return PermReport{}, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return PermReport{}, ErrDomainNotFound
	}

	// Allocate any missing gid/uids first -- the ownership model below depends
	// on them. migrateDomain self-locks for passwd uid writes, so it runs
	// before we take the perms lock (no nested lock).
	_, _, allocated, errs := p.migrateDomain(domain)
	if len(errs) > 0 {
		return PermReport{Domain: domain, Allocated: allocated}, fmt.Errorf("allocate ids: %s", strings.Join(errs, "; "))
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return PermReport{}, err
	}
	defer unlock()

	plan, err := p.domainPermPlan(domain)
	if err != nil {
		return PermReport{}, err
	}
	plan = append(plan, p.configPermPlan(domain)...)
	report := applyPlan(plan, true)
	report.Domain = domain
	report.Allocated = allocated
	report.Warnings = p.shadowWarnings(domain)
	return report, report.firstError()
}

// permModeBits are the mode bits the model prescribes and the checker
// compares: the permission bits plus setuid/setgid/sticky. Comparing
// info.Mode() whole would always mismatch on directories (ModeDir is set).
const permModeBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// CheckDomain is FixDomain's read-only sibling: it builds the same plans and
// reports where the tree has drifted from the security model, without
// allocating ids, creating directories, or touching modes or ownership. No
// lock is taken -- the plans are advisory, and a racing fix simply shows up
// as a clean re-check. Off-root only modes are compared (see checkPlan). A
// domain with no allocated gid is reported as a drift finding, not an error:
// the check must never allocate.
func (p Paths) CheckDomain(domain string) (PermReport, error) {
	if !ValidDomainName(domain) {
		return PermReport{}, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return PermReport{}, ErrDomainNotFound
	}

	report := PermReport{Domain: domain}
	plan, err := p.domainPermPlan(domain)
	switch {
	case errors.Is(err, identity.ErrNoGID):
		// The data-tree plan cannot be built; the config-tree plan below does
		// not depend on the gid and is still checked.
		report.Entries = append(report.Entries, PermResult{
			Path:    filepath.Join(p.Data, domain),
			Changed: true,
			GotUID:  -1,
			GotGID:  -1,
			Err:     "domain has no allocated gid (run userctl domain fix)",
		})
		plan = nil
	case err != nil:
		return PermReport{}, err
	}
	plan = append(plan, p.configPermPlan(domain)...)
	report.Entries = append(report.Entries, checkPlan(plan).Entries...)
	return report, nil
}

// checkPlan is applyPlan's read-only sibling: it stats each planned path and
// reports drift without changing anything. Changed=true means drifted.
// Off-root, ownership is not compared (mirroring applyPlan's chown skip --
// the uid/gid model is only meaningful under privilege separation) and every
// entry is marked Skipped; modes are always compared. A missing path is
// drift: plan file entries are built from existing files, so only
// directories can be missing.
func checkPlan(plan []permEntry) PermReport {
	root := os.Geteuid() == 0
	report := PermReport{}
	for _, e := range plan {
		res := PermResult{Path: e.Path, UID: e.UID, GID: e.GID, Mode: e.Mode, GotUID: -1, GotGID: -1}
		if !root {
			res.Skipped = true
		}

		info, statErr := os.Stat(e.Path)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				res.Changed = true
				res.Err = "missing"
			} else {
				res.Err = statErr.Error()
			}
			report.Entries = append(report.Entries, res)
			continue
		}

		res.GotMode = info.Mode() & permModeBits
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			res.GotUID = int(st.Uid)
			res.GotGID = int(st.Gid)
		}
		if res.GotMode != e.Mode&permModeBits {
			res.Changed = true
		}
		if root && (res.GotUID != e.UID || res.GotGID != e.GID) {
			res.Changed = true
		}
		report.Entries = append(report.Entries, res)
	}
	return report
}

// DriftCount returns the number of drifted entries in a check report (or,
// for an apply report, the number of paths actually changed).
func (r PermReport) DriftCount() int {
	n := 0
	for _, e := range r.Entries {
		if e.Changed {
			n++
		}
	}
	return n
}

// firstError returns the first per-path error in a report, or nil.
func (r PermReport) firstError() error {
	for _, e := range r.Entries {
		if e.Err != "" {
			return fmt.Errorf("%s: %s", e.Path, e.Err)
		}
	}
	return nil
}
