package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/auth/identity"
	"github.com/infodancer/maildancer/auth/passwd"
)

// DomainInfo describes a domain's effective admin-visible state.
type DomainInfo struct {
	Name      string
	AuthType  string
	StoreType string
	UserCount int
	GID       uint32
}

// defaultDomainConfig is the config.toml written for newly created domains.
// Field values match the programmatic defaults the daemons apply when the
// file is absent; writing them explicitly makes the domain self-describing.
const defaultDomainConfig = `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"
`

// DomainExists reports whether the domain directory exists in the config volume.
func (p Paths) DomainExists(name string) bool {
	info, err := os.Stat(filepath.Join(p.Config, name))
	return err == nil && info.IsDir()
}

// CreateDomain creates the on-disk anatomy for a new domain and returns the
// allocated gid:
//
//	{config}/{domain}/           config.toml, empty passwd, keys/
//	{data}/{domain}/             config.toml recording the gid, users/ maildir root
//
// Directory ownership for the data tree (root:{gid} with setgid per the mail
// security model) is applied here when running as root; off-root the structure
// and modes are created and ownership is left to FixDomain.
func (p Paths) CreateDomain(name string) (uint32, error) {
	if !ValidDomainName(name) {
		return 0, ErrInvalidDomainName
	}
	if p.DomainExists(name) {
		return 0, ErrDomainExists
	}

	domainPath := filepath.Join(p.Config, name)
	if err := os.MkdirAll(filepath.Join(domainPath, "keys"), 0o750); err != nil {
		return 0, fmt.Errorf("create domain directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(domainPath, "config.toml"), []byte(defaultDomainConfig), 0o640); err != nil {
		return 0, fmt.Errorf("write config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(domainPath, "passwd"), []byte("# Users for "+name+"\n"), 0o640); err != nil {
		return 0, fmt.Errorf("write passwd: %w", err)
	}

	// Identity allocation goes through the single identity code path, which
	// records the gid in the authoritative {config}/gid.toml -- not the data
	// tree. Allocate-once; a re-create of an existing domain is refused above.
	gid, err := p.idMgr().AllocateDomainGID(name)
	if err != nil {
		return 0, fmt.Errorf("allocate domain gid: %w", err)
	}
	dataDir := filepath.Join(p.Data, name)
	if err := os.MkdirAll(filepath.Join(dataDir, "users"), 0o750); err != nil {
		return 0, fmt.Errorf("create users directory: %w", err)
	}

	// Apply the security model to the shared data directories now (root:{gid}
	// 2750), so the tree is correct at creation and needs no post-hoc repair.
	// Ownership is a no-op off-root; modes still apply.
	if err := p.provisionDomainDataDirs(name); err != nil {
		return 0, fmt.Errorf("set data directory ownership: %w", err)
	}

	return gid, nil
}

// DeleteDomain removes a domain's config-volume directory. When the domain
// still has users, it refuses unless force is set; the error wraps
// ErrDomainHasUsers and includes the count.
//
// The gid.toml ledger entry is always reclaimed -- it is allocation metadata,
// not mail data, and must not outlive the domain. (If the data tree is kept, a
// later recreate re-adopts this gid from the on-disk data-dir group during
// `domain fix`.)
//
// The data volume (maildirs) is left in place by default: deleting domain
// configuration revokes access without destroying mail data. A forced delete is
// a full teardown and removes the data tree as well, so nothing is orphaned.
func (p Paths) DeleteDomain(name string, force bool) error {
	if !ValidDomainName(name) {
		return ErrInvalidDomainName
	}
	if !p.DomainExists(name) {
		return ErrDomainNotFound
	}

	if !force {
		users, err := passwd.ListUsers(filepath.Join(p.Config, name, "passwd"))
		if err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		if len(users) > 0 {
			return fmt.Errorf("%w: %d users", ErrDomainHasUsers, len(users))
		}
	}

	if err := os.RemoveAll(filepath.Join(p.Config, name)); err != nil {
		return fmt.Errorf("remove domain: %w", err)
	}

	// Reclaim the gid.toml ledger entry so it never references a deleted domain.
	if err := p.idMgr().RemoveDomainGID(name); err != nil {
		return fmt.Errorf("remove domain gid: %w", err)
	}

	// Remove the mail data tree only on a forced teardown. In a single-tree
	// deployment (Data == Config) the data already went with the config dir
	// above, so only a distinct data volume needs separate removal.
	if force && p.Data != "" && p.Data != p.Config {
		if err := os.RemoveAll(filepath.Join(p.Data, name)); err != nil {
			return fmt.Errorf("remove domain data: %w", err)
		}
	}
	return nil
}

// ListDomains returns summaries for every domain in the config volume.
func (p Paths) ListDomains() ([]DomainInfo, error) {
	entries, err := os.ReadDir(p.Config)
	if err != nil {
		if os.IsNotExist(err) {
			return []DomainInfo{}, nil
		}
		return nil, fmt.Errorf("read domains directory: %w", err)
	}

	domains := []DomainInfo{}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] == '.' {
			continue
		}
		info, err := p.GetDomain(entry.Name())
		if err != nil {
			// Skip entries that stopped being domains mid-listing.
			continue
		}
		domains = append(domains, *info)
	}
	return domains, nil
}

// GetDomain returns the admin-visible state of a single domain. Auth and
// store types come from the config-volume config.toml (defaults reported
// when absent); the gid comes from the data-volume config.toml.
func (p Paths) GetDomain(name string) (*DomainInfo, error) {
	if !ValidDomainName(name) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(name) {
		return nil, ErrDomainNotFound
	}

	info := &DomainInfo{Name: name, AuthType: "passwd", StoreType: "maildir"}

	configPath := filepath.Join(p.Config, name, "config.toml")
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			Auth struct {
				Type string `toml:"type"`
			} `toml:"auth"`
			MsgStore struct {
				Type string `toml:"type"`
			} `toml:"msgstore"`
		}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		if cfg.Auth.Type != "" {
			info.AuthType = cfg.Auth.Type
		}
		if cfg.MsgStore.Type != "" {
			info.StoreType = cfg.MsgStore.Type
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if gid, err := identity.DomainGID(p.Config, name); err == nil {
		info.GID = gid
	}

	users, err := passwd.ListUsers(filepath.Join(p.Config, name, "passwd"))
	if err == nil {
		info.UserCount = len(users)
	}

	return info, nil
}
