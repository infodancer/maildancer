// Package domain provides domain configuration and management for mail services.
// Each email domain has its own authentication agent and message storage.
package domain

import (
	"context"
	"errors"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
)

// MailAuthAgent extends AuthenticationAgent with mail-specific capabilities.
// It is the required auth type for a Domain — all domains use a MailAuthAgent
// so that mail-layer features (forwarding, aliases, etc.) are always available.
type MailAuthAgent interface {
	auth.AuthenticationAgent

	// ResolveForward returns forwarding targets for a localpart, walking the
	// three-level hierarchy: user-level → domain-level → system default.
	// Returns (nil, false) if no forwarding rule applies.
	ResolveForward(ctx context.Context, localpart string) ([]string, bool)
}

// Domain holds the configuration and agents for a single email domain.
type Domain struct {
	// Name is the domain name (e.g., "example.com").
	Name string

	// AuthAgent handles authentication and mail-specific lookups for this domain.
	AuthAgent MailAuthAgent

	// DeliveryAgent handles message delivery for this domain.
	DeliveryAgent msgstore.DeliveryAgent

	// MessageStore provides read access to stored messages for this domain.
	MessageStore msgstore.MessageStore
}

// Close releases resources held by the domain's agents.
func (d *Domain) Close() error {
	var errs []error

	if d.AuthAgent != nil {
		if err := d.AuthAgent.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// DeliveryAgent (MsgStore) may have Close() - check if it implements io.Closer
	if closer, ok := d.DeliveryAgent.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
