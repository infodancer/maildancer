package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Manager is the single allocation/write path for identity maps. userctl and
// webadmin each construct one and call into it; nothing else writes the maps.
//
// Config is the config-tree root (holds gid.toml and {domain}/uid.toml). Data
// is the data-tree root (holds the shared .uid-counter). uid and gid draw from
// the same counter, so the 10000+ id space never collides between them.
type Manager struct {
	Config string
	Data   string
}

// NewManager returns a Manager over the given config and data tree roots.
func NewManager(configPath, dataPath string) *Manager {
	return &Manager{Config: configPath, Data: dataPath}
}

// DomainGID reads the allocated gid for domain (ErrNoGID if absent).
func (m *Manager) DomainGID(domain string) (uint32, error) {
	return DomainGID(m.Config, domain)
}

// UserUID reads the allocated uid for localpart (ErrNoUID if absent).
func (m *Manager) UserUID(domain, localpart string) (uint32, error) {
	return UserUID(m.Config, domain, localpart)
}

// AllocateDomainGID allocates a fresh gid for domain from the shared counter and
// records it in gid.toml. It is allocate-once: if the domain already has a gid,
// it returns that gid and ErrGIDExists rather than minting a new one.
func (m *Manager) AllocateDomainGID(domain string) (uint32, error) {
	unlock, err := lockFile(gidMapPath(m.Config) + ".lock")
	if err != nil {
		return 0, err
	}
	defer unlock()

	cur, err := loadMap(gidMapPath(m.Config))
	if err != nil {
		return 0, err
	}
	if gid, ok := cur[domain]; ok {
		return gid, ErrGIDExists
	}
	gid, err := allocateID(m.Data)
	if err != nil {
		return 0, fmt.Errorf("allocate domain gid: %w", err)
	}
	cur[domain] = gid
	if err := storeMap(gidMapPath(m.Config), gidMapHeader, cur); err != nil {
		return 0, err
	}
	return gid, nil
}

// SetDomainGID records a specific gid for domain (used by migration to adopt an
// id already authoritative under the old layout). Idempotent when the recorded
// value matches; ErrGIDExists when a different gid is already recorded -- the
// allocate-once guard, since changing a live gid orphans the group's files.
func (m *Manager) SetDomainGID(domain string, gid uint32) error {
	unlock, err := lockFile(gidMapPath(m.Config) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	cur, err := loadMap(gidMapPath(m.Config))
	if err != nil {
		return err
	}
	if existing, ok := cur[domain]; ok {
		if existing == gid {
			return nil
		}
		return ErrGIDExists
	}
	cur[domain] = gid
	return storeMap(gidMapPath(m.Config), gidMapHeader, cur)
}

// AllocateUserUID allocates a fresh uid for localpart in domain and records it
// in {domain}/uid.toml. Allocate-once, like AllocateDomainGID.
func (m *Manager) AllocateUserUID(domain, localpart string) (uint32, error) {
	unlock, err := lockFile(uidMapPath(m.Config, domain) + ".lock")
	if err != nil {
		return 0, err
	}
	defer unlock()

	cur, err := loadMap(uidMapPath(m.Config, domain))
	if err != nil {
		return 0, err
	}
	if uid, ok := cur[localpart]; ok {
		return uid, ErrUIDExists
	}
	uid, err := allocateID(m.Data)
	if err != nil {
		return 0, fmt.Errorf("allocate user uid: %w", err)
	}
	cur[localpart] = uid
	if err := storeMap(uidMapPath(m.Config, domain), uidMapHeader, cur); err != nil {
		return 0, err
	}
	return uid, nil
}

// SetUserUID records a specific uid for localpart (migration adoption).
// Idempotent on match; ErrUIDExists on a conflicting recorded value.
func (m *Manager) SetUserUID(domain, localpart string, uid uint32) error {
	unlock, err := lockFile(uidMapPath(m.Config, domain) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	cur, err := loadMap(uidMapPath(m.Config, domain))
	if err != nil {
		return err
	}
	if existing, ok := cur[localpart]; ok {
		if existing == uid {
			return nil
		}
		return ErrUIDExists
	}
	cur[localpart] = uid
	return storeMap(uidMapPath(m.Config, domain), uidMapHeader, cur)
}

// RemoveUser deletes localpart's uid entry (on user deletion). A missing entry
// is not an error.
func (m *Manager) RemoveUser(domain, localpart string) error {
	unlock, err := lockFile(uidMapPath(m.Config, domain) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	cur, err := loadMap(uidMapPath(m.Config, domain))
	if err != nil {
		return err
	}
	if _, ok := cur[localpart]; !ok {
		return nil
	}
	delete(cur, localpart)
	return storeMap(uidMapPath(m.Config, domain), uidMapHeader, cur)
}

// lockFile takes an exclusive flock on a lock file, creating it if absent. The
// returned func releases and closes it. Blocks until the lock is granted, so
// concurrent userctl and webadmin writers serialize.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open identity lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock identity map: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
