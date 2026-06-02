// Package credentials resolves uid, gid, basePath, and storeType for a
// fully-qualified username from the per-domain config and passwd files.
//
// This logic is extracted from pop3d and imapd where it was duplicated.
package credentials

import (
	"fmt"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
)

// Info holds the resolved credentials for spawning a mail-session process.
type Info struct {
	UID       uint32
	GID       uint32
	BasePath  string // absolute path to the user's maildir root
	StoreType string // e.g. "maildir"
}

// Lookup resolves credentials for username (localpart@domain) using the
// per-domain config and passwd files under domainsPath.
//
// Resolution order (highest priority wins):
//   - GID:      postmaster file > config.toml
//   - BasePath: postmaster file DataPath > domainsDataPath/domain > domainDir/users
//
// domainsDataPath, if non-empty, is used to resolve relative MsgStore.BasePath
// values — matching the behaviour of FilesystemDomainProvider.WithDataPath.
// The postmaster file (if present) takes priority over domainsDataPath.
// Credential backend paths are always resolved relative to domainsPath.
func Lookup(domainsPath, domainsDataPath, localpart, domainName string) (*Info, error) {
	domainDir := filepath.Join(domainsPath, domainName)

	cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		// Treat missing config as empty — domain may use defaults.
		cfg = &domain.DomainConfig{}
	}

	// Resolve credential backend path (default: "passwd").
	credBackend := cfg.Auth.CredentialBackend
	if credBackend == "" {
		credBackend = "passwd"
	}
	passwdPath := credBackend
	if !filepath.IsAbs(passwdPath) {
		passwdPath = filepath.Join(domainDir, passwdPath)
	}

	uid, err := passwd.LookupUID(passwdPath, localpart)
	if err != nil {
		return nil, fmt.Errorf("lookup uid for %q in %q: %w", localpart, passwdPath, err)
	}

	gid := cfg.Gid

	// Resolve mail-session basePath (default: "users").
	// Priority: postmaster DataPath > domainsDataPath+domain > domainDir.
	storageBase := domainDir
	if domainsDataPath != "" {
		storageBase = filepath.Join(domainsDataPath, domainName)
	}

	base := cfg.MsgStore.BasePath
	if base == "" {
		base = "users"
	}

	// Postmaster file is authoritative for GID and data path.
	if entry := domain.LookupDomainPostmaster(domainsPath, domainName); entry != nil {
		if entry.GID != 0 {
			gid = entry.GID
		}
		if entry.DataPath != "" {
			storageBase = entry.DataPath
		}
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
