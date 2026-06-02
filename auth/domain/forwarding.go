package domain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/msgstore"
)

// forwardChain holds the three-level forwarding lookup hierarchy.
// Resolution order: user-level → domain-level → system default.
//
//   - User-level:     {domainPath}/user_forwards/{localpart}  (plain list, read on demand)
//   - Domain-level:   {domainPath}/forwards                   (localpart:targets)
//   - System default: {basePath}/forwards                     (localpart:targets)
//
// User-level files are read on every lookup so changes take effect without restart.
// Domain and default maps are loaded at domain init time.
type forwardChain struct {
	userForwardsDir string
	domainForwards  *forwards.ForwardMap
	defaultForwards *forwards.ForwardMap
}

// resolve returns forwarding targets for localpart, walking the chain in priority order.
func (c *forwardChain) resolve(localpart string) ([]string, bool) {
	// 1. User-level: {userForwardsDir}/{localpart}
	if c.userForwardsDir != "" {
		targets, err := forwards.LoadTargets(filepath.Join(c.userForwardsDir, localpart))
		if err == nil && len(targets) > 0 {
			return targets, true
		}
	}

	// 2. Domain-level
	if targets, ok := c.domainForwards.Resolve(localpart); ok {
		return targets, true
	}

	// 3. System default
	if targets, ok := c.defaultForwards.Resolve(localpart); ok {
		return targets, true
	}

	return nil, false
}

// mailAuthAgent implements MailAuthAgent. It wraps an AuthenticationAgent and
// extends UserExists to return true for forward-only addresses, and exposes
// ResolveForward so callers can inspect the forwarding chain without knowing
// its internal structure.
//
// Authenticate always delegates to the inner agent — forward-only addresses
// have no credentials and cannot log in.
type mailAuthAgent struct {
	inner auth.AuthenticationAgent
	chain *forwardChain
}

// Compile-time check: mailAuthAgent must satisfy MailAuthAgent.
var _ MailAuthAgent = (*mailAuthAgent)(nil)

func (a *mailAuthAgent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	return a.inner.Authenticate(ctx, username, password)
}

// UserExists returns true if the user exists in the inner agent OR if the
// localpart has a forwarding rule at any level of the chain.
func (a *mailAuthAgent) UserExists(ctx context.Context, username string) (bool, error) {
	exists, err := a.inner.UserExists(ctx, username)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	_, ok := a.chain.resolve(username)
	return ok, nil
}

// ResolveForward returns forwarding targets for localpart by walking the chain.
func (a *mailAuthAgent) ResolveForward(_ context.Context, localpart string) ([]string, bool) {
	return a.chain.resolve(localpart)
}

func (a *mailAuthAgent) Close() error {
	return a.inner.Close()
}

// GetPublicKey delegates to the inner agent if it implements KeyProvider.
// Forward-only addresses have no keys.
func (a *mailAuthAgent) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	if kp, ok := a.inner.(auth.KeyProvider); ok {
		return kp.GetPublicKey(ctx, username)
	}
	return nil, autherrors.ErrKeyNotFound
}

// HasEncryption delegates to the inner agent if it implements KeyProvider.
func (a *mailAuthAgent) HasEncryption(ctx context.Context, username string) (bool, error) {
	if kp, ok := a.inner.(auth.KeyProvider); ok {
		return kp.HasEncryption(ctx, username)
	}
	return false, nil
}

// MailDeliveryAgent is a msgstore.DeliveryAgent that applies mail-routing
// logic before delivering to the underlying store. It handles:
//
//   - Forwarding rule resolution and expansion via the three-level forwardChain
//   - Routing forwarded messages to the correct domain's DeliveryAgent
//
// Future capabilities may include: relay routing, alias expansion, per-user
// filtering, and quota enforcement.
//
// smtpd is entirely unaware of this logic — it simply calls Deliver() and the
// MailDeliveryAgent handles all routing decisions.
//
// Note: loop detection is not implemented. Avoid circular forwarding rules.
type MailDeliveryAgent struct {
	inner    msgstore.DeliveryAgent
	chain    *forwardChain
	provider DomainProvider
}

// Deliver resolves any forwarding rules for the recipient and routes accordingly.
//
//   - No forward match: deliver locally via the inner agent.
//   - Forward match: buffer and deliver to each target via its domain's DeliveryAgent.
//   - Target on an unserved domain: returns an error (no outbound relay available).
func (a *MailDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if len(envelope.Recipients) == 0 {
		return a.inner.Deliver(ctx, envelope, message)
	}

	// smtpd enforces one recipient per message; handle all defensively.
	to := envelope.Recipients[0]
	localpart, _ := SplitUsername(to)

	targets, forwarded := a.chain.resolve(localpart)
	if !forwarded {
		return a.inner.Deliver(ctx, envelope, message)
	}

	// Buffer the message body so it can be re-read for each forward target.
	data, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("buffer message for forwarding: %w", err)
	}

	var errs []error
	for _, target := range targets {
		_, targetDomain := SplitUsername(target)
		if targetDomain == "" {
			errs = append(errs, fmt.Errorf("forward target %q has no domain", target))
			continue
		}

		d := a.provider.GetDomain(targetDomain)
		if d == nil || d.DeliveryAgent == nil {
			errs = append(errs, fmt.Errorf("forward to %q: domain %q is not locally served (no outbound relay)", target, targetDomain))
			continue
		}

		fwdEnvelope := envelope
		fwdEnvelope.Recipients = []string{target}
		if err := d.DeliveryAgent.Deliver(ctx, fwdEnvelope, bytes.NewReader(data)); err != nil {
			errs = append(errs, fmt.Errorf("forward to %q: %w", target, err))
		}
	}
	return errors.Join(errs...)
}
