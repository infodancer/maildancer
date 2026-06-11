// Package admin is the shared administrative operations layer for domain and
// user management. Both webadmin (HTTP) and userctl (CLI) call this package,
// so the two tools cannot drift on security-sensitive flows: passwd file
// edits, uid/gid allocation, domain directory anatomy, and key management
// all live here exactly once.
//
// The package is a library: it does no logging and no privilege checks.
// Authorization (RBAC in webadmin, process identity for the CLI) and audit
// logging are the callers' responsibility. Mutating operations serialize
// across processes via a per-domain flock (see lock.go), so a webadmin
// instance and a userctl invocation cannot corrupt a passwd file by racing.
package admin

import (
	"errors"
	"path/filepath"
)

// Paths locates the volume roots of a deployment (see
// infodancer docs/deployment-filesystem.md).
//
// Config holds per-domain configuration: config.toml, passwd, keys/.
// Data holds runtime data: maildirs, the uid counter, gid records.
// Single-tree deployments set both to the same directory.
type Paths struct {
	Config string
	Data   string
}

// DomainDir returns the config-volume directory for a domain.
func (p Paths) DomainDir(domain string) string {
	return filepath.Join(p.Config, domain)
}

// Sentinel errors. Callers map these to HTTP status codes or CLI messages.
var (
	ErrDomainNotFound    = errors.New("domain not found")
	ErrDomainExists      = errors.New("domain already exists")
	ErrDomainHasUsers    = errors.New("domain has users")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserExists        = errors.New("user already exists")
	ErrInvalidDomainName = errors.New("invalid domain name")
	ErrInvalidUsername   = errors.New("invalid username")
	ErrWeakPassword      = errors.New("password does not meet minimum requirements")
	ErrPasswordRequired  = errors.New("password is required")
)
