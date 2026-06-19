package admin

import "github.com/infodancer/maildancer/auth/identity"

// idMgr returns the identity Manager over this Paths' config and data trees.
// admin (driving userctl and webadmin) is one of the two entry points to the
// single identity allocation code path; it never reads or writes the gid.toml /
// uid.toml maps directly. See infodancer/docs/identity-allocation-design.md.
func (p Paths) idMgr() *identity.Manager {
	return identity.NewManager(p.Config, p.Data)
}
