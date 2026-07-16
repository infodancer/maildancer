package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/auth/identity"
	"github.com/infodancer/maildancer/auth/passwd"
)

// MigrateResult summarizes a MigrateUIDs run.
type MigrateResult struct {
	DomainsMigrated int
	UsersMigrated   int
	// Details records each allocation as "domain gid=N" or "user@domain uid=N".
	Details []string
	// Errors collects per-domain failures; migration continues past them.
	Errors []string
}

// MigrateUIDs walks every domain, ensuring each has a gid in gid.toml and each
// passwd user has a uid in uid.toml. Existing ids are adopted (so the on-disk
// mail is never re-chowned out from under itself); only genuinely unallocated
// domains/users draw a fresh id. Per-domain failures are recorded rather than
// aborting the walk.
func (p Paths) MigrateUIDs() (*MigrateResult, error) {
	result := &MigrateResult{Details: []string{}, Errors: []string{}}

	entries, err := os.ReadDir(p.Config)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, fmt.Errorf("read domains directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] == '.' {
			continue
		}
		name := entry.Name()

		domainMigrated, usersMigrated, details, errs := p.migrateDomain(name)
		if domainMigrated {
			result.DomainsMigrated++
		}
		result.UsersMigrated += usersMigrated
		result.Details = append(result.Details, details...)
		result.Errors = append(result.Errors, errs...)
	}

	return result, nil
}

// migrateDomain ensures one domain has a gid (gid.toml) and all its users have
// uids (uid.toml), adopting any value already authoritative under the old
// layout before allocating a fresh one.
func (p Paths) migrateDomain(name string) (domainMigrated bool, usersMigrated int, details, errs []string) {
	mgr := p.idMgr()

	// GID: adopt an existing value or allocate a fresh one.
	if _, err := identity.DomainGID(p.Config, name); errors.Is(err, identity.ErrNoGID) {
		if gid, src := p.adoptDomainGID(name); gid != 0 {
			if err := mgr.SetDomainGID(name, gid); err != nil {
				errs = append(errs, fmt.Sprintf("%s: record adopted gid: %v", name, err))
			} else {
				domainMigrated = true
				details = append(details, fmt.Sprintf("%s gid=%d (adopted from %s)", name, gid, src))
			}
		} else {
			gid, err := mgr.AllocateDomainGID(name)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: allocate gid: %v", name, err))
			} else {
				domainMigrated = true
				details = append(details, fmt.Sprintf("%s gid=%d (allocated)", name, gid))
			}
		}
	} else if err != nil {
		errs = append(errs, fmt.Sprintf("%s: read gid: %v", name, err))
	}

	migrated, userDetails, uerrs := p.migrateUserUIDs(name)
	usersMigrated = migrated
	details = append(details, userDetails...)
	errs = append(errs, uerrs...)

	// Narrow legacy four-field passwd entries to user:hash:mailbox now that the
	// uid is authoritative in uid.toml.
	stripped, serrs := p.stripMigratedPasswdUIDs(name)
	errs = append(errs, serrs...)
	if stripped > 0 {
		details = append(details, fmt.Sprintf("%s narrowed %d legacy passwd uid field(s)", name, stripped))
	}
	return domainMigrated, usersMigrated, details, errs
}

// stripMigratedPasswdUIDs drops the legacy uid column from passwd entries whose
// uid is already recorded in uid.toml -- the only safe condition, since the
// passwd uid is otherwise the sole record. Runs under the domain lock.
func (p Paths) stripMigratedPasswdUIDs(domain string) (int, []string) {
	passwdPath := filepath.Join(p.Config, domain, "passwd")
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		return 0, []string{fmt.Sprintf("%s: list users for strip: %v", domain, err)}
	}
	// A user is safe to strip once their uid is in uid.toml -- regardless of the
	// passwd column's value (a stale ":0" included). StripUIDs only narrows
	// genuine four-field lines, so passing an already-three-field user is a
	// no-op. A user NOT in uid.toml is left untouched so their uid is not lost.
	var safe []string
	for _, u := range users {
		if _, err := identity.UserUID(p.Config, domain, u.Username); err == nil {
			safe = append(safe, u.Username)
		}
	}
	if len(safe) == 0 {
		return 0, nil
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return 0, []string{fmt.Sprintf("%s: lock for passwd strip: %v", domain, err)}
	}
	defer unlock()

	n, err := passwd.StripUIDs(passwdPath, safe)
	if err != nil {
		return 0, []string{fmt.Sprintf("%s: strip passwd uids: %v", domain, err)}
	}
	return n, nil
}

// migrateUserUIDs ensures every passwd user has a uid in uid.toml, adopting the
// legacy passwd-4th-field uid when present, else allocating fresh.
func (p Paths) migrateUserUIDs(domain string) (migrated int, details, errs []string) {
	passwdPath := filepath.Join(p.Config, domain, "passwd")
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, []string{fmt.Sprintf("%s: list users: %v", domain, err)}
	}

	mgr := p.idMgr()
	for _, u := range users {
		if _, err := identity.UserUID(p.Config, domain, u.Username); !errors.Is(err, identity.ErrNoUID) {
			continue // already allocated (or a read error we leave to perms)
		}
		if u.Uid != 0 {
			if err := mgr.SetUserUID(domain, u.Username, u.Uid); err != nil {
				errs = append(errs, fmt.Sprintf("%s@%s: record adopted uid: %v", u.Username, domain, err))
				continue
			}
			migrated++
			details = append(details, fmt.Sprintf("%s@%s uid=%d (adopted from passwd)", u.Username, domain, u.Uid))
			continue
		}
		uid, err := mgr.AllocateUserUID(domain, u.Username)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s@%s: allocate uid: %v", u.Username, domain, err))
			continue
		}
		migrated++
		details = append(details, fmt.Sprintf("%s@%s uid=%d (allocated)", u.Username, domain, uid))
	}
	return migrated, details, errs
}

// adoptDomainGID finds a domain's authoritative gid under the pre-identity-map
// layout, in priority order, and reports the source. Returns 0 when none is
// found (the caller then allocates fresh).
//
// The on-disk group of the data directory wins: adopting it means the reconcile
// chown is a no-op, so a live domain's mail is never re-grouped out from under
// the running daemons. Below that come the retired record locations.
func (p Paths) adoptDomainGID(domain string) (gid uint32, source string) {
	dataDir := filepath.Join(p.Data, domain)

	// 1. Actual group ownership of the data directory.
	if info, err := os.Stat(dataDir); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Gid >= firstReservedGID {
			return st.Gid, "data dir group"
		}
	}
	// 2. Retired data-tree config.toml `[domain] gid`.
	if g := tomlDomainGID(filepath.Join(dataDir, "config.toml")); g != 0 {
		return g, "data-tree config.toml"
	}
	// 3. Retired config-tree config.toml top-level `gid`.
	if g := tomlTopLevelGID(filepath.Join(p.Config, domain, "config.toml")); g != 0 {
		return g, "config-tree config.toml"
	}
	return 0, ""
}

// firstReservedGID is the lowest gid the allocator hands out; a data dir owned
// by a lower gid (e.g. root) is not a real domain allocation to adopt.
const firstReservedGID = uint32(10000)

// Service accounts baked into the all-in-one Docker image. The unprivileged
// daemons run under these fixed ids so that image rebuilds never reshuffle
// ownership of anything they touch. They must stay below firstReservedGID
// (the 10000 allocator floor) so they can never collide with an allocated
// per-domain gid or per-user uid.
const (
	// MailsvcGID is the shared service group for the unprivileged daemons.
	MailsvcGID = uint32(900)
	// CfgreadGID is the dedicated config-tree read group: an explicit grant
	// for the tree's nonroot readers (auth-oidc via compose group_add,
	// queued in the image). Deliberately not 65532 -- running as distroless
	// nonroot must not convey config-tree access by accident (issue #152).
	CfgreadGID = uint32(906)

	// Pop3dUID is the pop3d daemon's service account.
	Pop3dUID = uint32(901)
	// ImapdUID is the imapd daemon's service account.
	ImapdUID = uint32(902)
	// SmtpdUID is the smtpd daemon's service account.
	SmtpdUID = uint32(903)
	// QueuedUID is the queue-manager daemon's service account.
	QueuedUID = uint32(904)
	// WebadminUID is the webadmin daemon's service account.
	WebadminUID = uint32(905)
)

// tomlDomainGID reads `[domain] gid` from a TOML file; 0 if absent/unreadable.
func tomlDomainGID(path string) uint32 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var c struct {
		Domain struct {
			Gid uint32 `toml:"gid"`
		} `toml:"domain"`
	}
	if err := toml.Unmarshal(data, &c); err != nil {
		return 0
	}
	return c.Domain.Gid
}

// tomlTopLevelGID reads a top-level `gid` from a TOML file; 0 if absent. The
// gid field was removed from DomainConfig (maildancer#101); this ad-hoc parse
// exists only to adopt the legacy value during migration.
func tomlTopLevelGID(path string) uint32 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var c struct {
		Gid uint32 `toml:"gid"`
	}
	if err := toml.Unmarshal(data, &c); err != nil {
		return 0
	}
	return c.Gid
}
