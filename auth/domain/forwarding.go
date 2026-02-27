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
//   - User-level:   {domainPath}/user_forwards/{localpart}   (plain list of targets, one per line)
//   - Domain-level: {domainPath}/forwards                    (localpart:targets file)
//   - System default: {basePath}/forwards                    (localpart:targets file)
//
// User-level files are read on demand (not cached), so changes take effect
// without a restart. Domain and default maps are loaded at domain init time.
type forwardChain struct {
	userForwardsDir string            // directory containing per-user forward files
	domainForwards  *forwards.ForwardMap
	defaultForwards *forwards.ForwardMap
}

// resolve returns forwarding targets for localpart, walking the chain in order.
// Returns (nil, false) if no rule matches at any level.
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

// userExists reports whether localpart has a forwarding rule at any level.
func (c *forwardChain) userExists(localpart string) bool {
	_, ok := c.resolve(localpart)
	return ok
}

// forwardingAuthAgent wraps an AuthenticationAgent to include forward-only
// addresses in UserExists checks. Authenticate still requires the user to
// exist in the inner agent — forward-only addresses cannot authenticate.
type forwardingAuthAgent struct {
	inner auth.AuthenticationAgent
	chain *forwardChain
}

// Authenticate delegates to the inner agent unchanged.
// Forward-only addresses have no credentials and cannot log in.
func (a *forwardingAuthAgent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	return a.inner.Authenticate(ctx, username, password)
}

// UserExists returns true if the user exists in the inner agent OR if the
// localpart has a forwarding rule at any level of the chain.
func (a *forwardingAuthAgent) UserExists(ctx context.Context, username string) (bool, error) {
	exists, err := a.inner.UserExists(ctx, username)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	return a.chain.userExists(username), nil
}

// Close delegates to the inner agent.
func (a *forwardingAuthAgent) Close() error {
	return a.inner.Close()
}

// GetPublicKey delegates to the inner agent if it implements KeyProvider.
// Forward-only addresses have no keys.
func (a *forwardingAuthAgent) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	if kp, ok := a.inner.(auth.KeyProvider); ok {
		return kp.GetPublicKey(ctx, username)
	}
	return nil, autherrors.ErrKeyNotFound
}

// HasEncryption delegates to the inner agent if it implements KeyProvider.
// Forward-only addresses are treated as having no encryption.
func (a *forwardingAuthAgent) HasEncryption(ctx context.Context, username string) (bool, error) {
	if kp, ok := a.inner.(auth.KeyProvider); ok {
		return kp.HasEncryption(ctx, username)
	}
	return false, nil
}

// forwardingDeliveryAgent wraps a DeliveryAgent to expand forwarding rules
// before delivery. It routes forwarded messages to the correct domain's
// DeliveryAgent via the DomainProvider.
//
// smtpd enforces one recipient per message, so in practice the envelope
// contains exactly one recipient. Multiple recipients are handled defensively.
//
// Loop detection is not implemented. Avoid circular forwarding rules.
type forwardingDeliveryAgent struct {
	inner    msgstore.DeliveryAgent
	chain    *forwardChain
	provider DomainProvider
}

// Deliver checks forwarding rules for the first recipient and routes accordingly.
//
//   - No forward match → delivered locally via the inner agent.
//   - Forward match → message is buffered and delivered to each target via its
//     domain's DeliveryAgent. Targets on domains not served locally result in an
//     error (no outbound relay is available).
func (a *forwardingDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if len(envelope.Recipients) == 0 {
		return a.inner.Deliver(ctx, envelope, message)
	}

	// Use first recipient to resolve forwarding (smtpd sends one at a time).
	to := envelope.Recipients[0]
	localpart, _ := SplitUsername(to)

	targets, forwarded := a.chain.resolve(localpart)
	if !forwarded {
		return a.inner.Deliver(ctx, envelope, message)
	}

	// Buffer the message so it can be re-read for each forward target.
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
