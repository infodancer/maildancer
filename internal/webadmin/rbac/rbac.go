package rbac

import (
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Role represents an admin role type.
type Role string

const (
	RoleSuperAdmin  Role = "super_admin"
	RoleDomainAdmin Role = "domain_admin"
)

// AdminEntry holds role configuration for a single admin.
type AdminEntry struct {
	Role    Role     `toml:"role"`
	Domains []string `toml:"domains"`
}

// RoleStore holds loaded role assignments.
type RoleStore struct {
	Admins map[string]AdminEntry `toml:"admins"`
}

// LoadRoles reads and parses a roles.toml file.
// Returns an empty RoleStore (treating all as super_admin) if path is "".
func LoadRoles(path string) (*RoleStore, error) {
	rs := &RoleStore{
		Admins: make(map[string]AdminEntry),
	}
	if path == "" {
		return rs, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := toml.Unmarshal(data, rs); err != nil {
		return nil, err
	}
	if rs.Admins == nil {
		rs.Admins = make(map[string]AdminEntry)
	}
	return rs, nil
}

// IsSuperAdmin returns true if the username has super_admin role,
// OR if the username has no entry in the store (backward-compatible default).
func (rs *RoleStore) IsSuperAdmin(username string) bool {
	entry, ok := rs.Admins[username]
	if !ok {
		return true
	}
	return entry.Role == RoleSuperAdmin
}

// CanAccessDomain returns true if username can access the given domain.
// Super admins can access all domains. Domain admins can only access their assigned domains.
// Unknown users return false.
func (rs *RoleStore) CanAccessDomain(username, domain string) bool {
	entry, ok := rs.Admins[username]
	if !ok {
		return false
	}
	if entry.Role == RoleSuperAdmin {
		return true
	}
	for _, d := range entry.Domains {
		if d == domain {
			return true
		}
	}
	return false
}

// FilterDomains returns only the domains the username can access from the given list.
func (rs *RoleStore) FilterDomains(username string, domains []string) []string {
	if len(domains) == 0 {
		return []string{}
	}
	if rs.IsSuperAdmin(username) {
		result := make([]string, len(domains))
		copy(result, domains)
		return result
	}
	var result []string
	for _, d := range domains {
		if rs.CanAccessDomain(username, d) {
			result = append(result, d)
		}
	}
	if result == nil {
		return []string{}
	}
	return result
}
