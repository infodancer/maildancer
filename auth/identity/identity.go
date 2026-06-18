// Package identity is the single read/write code path for OS uid/gid
// allocation in the local passwd-files auth provider.
//
// uid/gid are identity allocation, NOT configuration: they are exempt from the
// site->domain->user config merge hierarchy. A domain's gid lives in one
// top-level map, {config}/gid.toml; a user's uid lives in the per-domain map
// {config}/{domain}/uid.toml. Both are flat and authoritative -- never merged,
// never defaulted. Reading the spawn identity for a missing entry is a hard
// error, never a fallback.
//
// This package is the ONLY writer of those maps. userctl (CLI) and webadmin
// (web UI) are entry points that construct a Manager and call into it; nothing
// else allocates, copies, or caches a uid/gid. The daemons import the read-only
// free functions (DomainGID, UserUID) to resolve spawn credentials.
//
// See infodancer/infodancer/docs/identity-allocation-design.md for the contract
// and its guard rules. Do not reintroduce a gid into config.toml, the
// postmaster file, or the data tree.
package identity

import (
	"errors"
	"path/filepath"
)

// Map file names, relative to the config tree.
const (
	// GIDMapFile is the top-level domain->gid map: {config}/gid.toml.
	GIDMapFile = "gid.toml"
	// UIDMapFile is the per-domain user->uid map: {config}/{domain}/uid.toml.
	UIDMapFile = "uid.toml"
)

// Sentinel errors. Callers distinguish "not allocated" (a hard error at spawn)
// from "already allocated" (the allocate-once guard tripping).
var (
	// ErrNoGID is returned when a domain has no allocated gid.
	ErrNoGID = errors.New("identity: domain has no allocated gid")
	// ErrNoUID is returned when a user has no allocated uid.
	ErrNoUID = errors.New("identity: user has no allocated uid")
	// ErrGIDExists is returned when allocating a gid for a domain that already
	// has a different one -- reassigning a live gid orphans the group's files.
	ErrGIDExists = errors.New("identity: domain gid already allocated")
	// ErrUIDExists is returned when allocating a uid for a user that already
	// has a different one -- reassigning a live uid orphans the user's mail.
	ErrUIDExists = errors.New("identity: user uid already allocated")
)

// gidMapPath returns {config}/gid.toml.
func gidMapPath(configPath string) string {
	return filepath.Join(configPath, GIDMapFile)
}

// uidMapPath returns {config}/{domain}/uid.toml.
func uidMapPath(configPath, domain string) string {
	return filepath.Join(configPath, domain, UIDMapFile)
}

// DomainGID reads the allocated gid for domain from {config}/gid.toml. It
// returns ErrNoGID when the domain has no entry -- a hard error, since the
// daemon cannot spawn mail-session without a gid. No merge, no default.
func DomainGID(configPath, domain string) (uint32, error) {
	m, err := loadMap(gidMapPath(configPath))
	if err != nil {
		return 0, err
	}
	gid, ok := m[domain]
	if !ok {
		return 0, ErrNoGID
	}
	return gid, nil
}

// UserUID reads the allocated uid for localpart from {config}/{domain}/uid.toml.
// It returns ErrNoUID when the user has no entry. No merge, no default.
func UserUID(configPath, domain, localpart string) (uint32, error) {
	m, err := loadMap(uidMapPath(configPath, domain))
	if err != nil {
		return 0, err
	}
	uid, ok := m[localpart]
	if !ok {
		return 0, ErrNoUID
	}
	return uid, nil
}
