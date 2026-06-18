package admin

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/auth/passwd"
)

// shadowWarnings reports real (passwd) users whose mail is also captured by a
// forward rule. A forward at any per-domain tier (admin config.toml [forwards],
// the domain forwards file, or the user's own user_forwards entry) shadows the
// mailbox: delivery resolves the forward upstream in session-manager and never
// writes to the local maildir, so the account silently receives no mail. A
// domain or admin catchall (*) shadows every user, which is the common
// contradiction (a real account plus a catchall that funnels everything away).
//
// The global system-default forward tier is deliberately not consulted here:
// it is a site-wide policy, not a per-domain misconfiguration, and flagging
// every user in every domain against it would be noise.
//
// Returns one human-readable warning per shadowed user. Resolution errors are
// non-fatal: a tier that cannot be read contributes nothing.
func (p Paths) shadowWarnings(domainName string) []string {
	domainDir := filepath.Join(p.Config, domainName)

	users, err := passwd.ListUsers(filepath.Join(domainDir, "passwd"))
	if err != nil || len(users) == 0 {
		return nil
	}

	// Admin tier: per-domain config.toml [forwards].
	var adminFwd *forwards.ForwardMap
	if cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml")); err == nil {
		adminFwd = forwards.FromMap(cfg.Forwards)
	} else {
		adminFwd = forwards.FromMap(nil)
	}

	// Domain tier: the forwards file (missing file -> empty, not an error).
	domainFwd, err := forwards.Load(filepath.Join(domainDir, "forwards"))
	if err != nil {
		domainFwd = forwards.FromMap(nil)
	}

	userForwardsDir := filepath.Join(domainDir, "user_forwards")

	var warnings []string
	for _, u := range users {
		tier, targets := shadowingTier(adminFwd, domainFwd, userForwardsDir, u.Username)
		if tier == "" {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"user %s@%s has a mailbox but is also forwarded (%s -> %s); mail is forwarded away and never delivered to the mailbox",
			u.Username, domainName, tier, strings.Join(targets, ", ")))
	}
	return warnings
}

// shadowingTier returns the highest-priority tier that forwards localpart and
// its targets, or ("", nil) if no per-domain tier covers it. Order matches the
// delivery chain: admin -> domain -> user.
func shadowingTier(adminFwd, domainFwd *forwards.ForwardMap, userForwardsDir, localpart string) (string, []string) {
	if targets, ok := adminFwd.Resolve(localpart); ok {
		return "admin config.toml [forwards]", targets
	}
	if targets, ok := domainFwd.Resolve(localpart); ok {
		return "domain forwards file", targets
	}
	if targets, err := forwards.LoadTargets(filepath.Join(userForwardsDir, localpart)); err == nil && len(targets) > 0 {
		return "user_forwards", targets
	}
	return "", nil
}
