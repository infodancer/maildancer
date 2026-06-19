// Package credentials resolves uid, gid, basePath, and storeType for a
// fully-qualified username from the per-domain identity maps and config.
//
// This logic is extracted from pop3d and imapd where it was duplicated.
package credentials

import (
	"fmt"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/identity"
)

// Info holds the resolved credentials for spawning a mail-session process.
type Info struct {
	UID       uint32
	GID       uint32
	BasePath  string // absolute path to the user's maildir root
	StoreType string // e.g. "maildir"
}

// Lookup resolves credentials for username (localpart@domain) for the local
// passwd-files provider.
//
// Identity (uid/gid) is read from the authoritative maps and is NOT subject to
// any merge, default, or fallback -- a missing entry is a hard error:
//   - GID: {domainsPath}/gid.toml             (domain -> gid)
//   - UID: {domainsPath}/{domain}/uid.toml    (localpart -> uid)
//
// Configuration (store type, base path) comes from the hierarchical
// per-domain config.toml. domainsDataPath, if non-empty, is the data-tree root
// used to resolve a relative MsgStore.BasePath; otherwise the config-tree
// domain dir is used.
//
// There is deliberately no gid from config.toml, no data-tree gid override, and
// no postmaster-file override -- those three layered sources were the homelab
// "permission denied" bug (maildancer#101). See
// infodancer/docs/identity-allocation-design.md.
func Lookup(domainsPath, domainsDataPath, localpart, domainName string) (*Info, error) {
	domainDir := filepath.Join(domainsPath, domainName)

	cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		// Treat missing config as empty -- store type/base fall back to
		// defaults. Identity, below, has no such fallback.
		cfg = &domain.DomainConfig{}
	}

	gid, err := identity.DomainGID(domainsPath, domainName)
	if err != nil {
		return nil, fmt.Errorf("resolve gid for domain %q: %w", domainName, err)
	}

	uid, err := identity.UserUID(domainsPath, domainName, localpart)
	if err != nil {
		return nil, fmt.Errorf("resolve uid for %q@%q: %w", localpart, domainName, err)
	}

	// Resolve mail-session basePath (configuration, not identity).
	storageBase := domainDir
	if domainsDataPath != "" {
		storageBase = filepath.Join(domainsDataPath, domainName)
	}
	base := cfg.MsgStore.BasePath
	if base == "" {
		base = "users"
	}
	if !filepath.IsAbs(base) {
		base = filepath.Join(storageBase, base)
	}

	storeType := cfg.MsgStore.Type
	if storeType == "" {
		storeType = "maildir"
	}

	return &Info{
		UID:       uid,
		GID:       gid,
		BasePath:  base,
		StoreType: storeType,
	}, nil
}
