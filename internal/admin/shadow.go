package admin

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/auth/passwd"
)

// shadowWarnings reports real (passwd) users whose mail is swept away by a
// wildcard catchall (*) they did not explicitly opt into. A real mailbox that
// forwards elsewhere is the classic, intentional case of mail forwarding and is
// NOT flagged: an explicit per-user forward (admin config.toml [forwards], the
// domain forwards file, or the user's own user_forwards entry) is deliberate.
// Only a bare catchall, which redirects an account the operator may not have
// meant to capture, is surfaced -- delivery resolves the catchall upstream in
// session-manager and never writes to the local maildir.
//
// The global system-default forward tier is deliberately not consulted here:
// it is a site-wide policy, not a per-domain misconfiguration, and flagging
// every user in every domain against it would be noise.
//
// Returns one human-readable warning per catchall-shadowed user. Resolution
// errors are non-fatal: a tier that cannot be read contributes nothing.
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
		tier, targets := catchallShadow(adminFwd, domainFwd, userForwardsDir, u.Username)
		if tier == "" {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"user %s@%s has a mailbox but a %s catchall (*) forwards their mail away (-> %s); add an explicit forward or exclude them from the catchall if the mailbox should receive mail",
			u.Username, domainName, tier, strings.Join(targets, ", ")))
	}
	return warnings
}

// catchallShadow returns the tier whose wildcard catchall captures localpart
// when the user has no intentional forward of their own, or ("", nil)
// otherwise. An explicit per-user forward (admin/domain exact, or a
// user_forwards entry) is deliberate forwarding and is never flagged.
func catchallShadow(adminFwd, domainFwd *forwards.ForwardMap, userForwardsDir, localpart string) (string, []string) {
	// Intentional per-user forwarding: not a shadow.
	if adminFwd.HasExact(localpart) || domainFwd.HasExact(localpart) {
		return "", nil
	}
	if targets, err := forwards.LoadTargets(filepath.Join(userForwardsDir, localpart)); err == nil && len(targets) > 0 {
		return "", nil
	}
	// A catchall sweeps the user up without an explicit rule.
	if targets, ok := adminFwd.Catchall(); ok {
		return "admin config.toml [forwards]", targets
	}
	if targets, ok := domainFwd.Catchall(); ok {
		return "domain forwards file", targets
	}
	return "", nil
}
