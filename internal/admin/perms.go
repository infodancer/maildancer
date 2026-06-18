package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

// permEntry is one path's desired ownership and mode.
type permEntry struct {
	Path string
	UID  int
	GID  int
	Mode os.FileMode
}

// PermReport records what a permission apply/check did or would do.
type PermReport struct {
	Domain  string
	Entries []PermResult
}

// PermResult is the per-path outcome of an apply.
type PermResult struct {
	Path    string
	UID     int
	GID     int
	Mode    os.FileMode
	Changed bool   // ownership/mode actually changed
	Skipped bool   // not applied (e.g. chown without privilege)
	Err     string // non-empty when this path could not be fully fixed
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
	if gid == 0 {
		return nil, fmt.Errorf("domain %s has no gid allocated", domain)
	}

	dataDir := filepath.Join(p.Data, domain)
	usersDir := filepath.Join(dataDir, "users")
	plan := []permEntry{
		{Path: dataDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
		{Path: usersDir, UID: rootUID, GID: int(gid), Mode: sharedDirMode},
	}

	// Each user with an allocated uid gets their own directory owned uid:gid.
	users, err := passwd.ListUsers(filepath.Join(p.Config, domain, "passwd"))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		if u.Uid == 0 {
			continue // pre-migration entry with no uid; nothing to own
		}
		plan = append(plan, permEntry{
			Path: filepath.Join(usersDir, u.Username),
			UID:  int(u.Uid),
			GID:  int(gid),
			Mode: userDirMode,
		})
	}
	return plan, nil
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

// FixDomainPerms checks and repairs ownership/modes across a domain's data tree
// against the security model, idempotently. It is the supported replacement for
// the standalone fix-domain-perms.sh: it resolves the gid from the data tree
// (where it lives) and never silently skips a configured domain. Returns a
// report of every path touched.
func (p Paths) FixDomainPerms(domain string) (PermReport, error) {
	if !ValidDomainName(domain) {
		return PermReport{}, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return PermReport{}, ErrDomainNotFound
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
	report := applyPlan(plan, true)
	report.Domain = domain
	return report, report.firstError()
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
