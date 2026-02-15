// Package domain provides domain configuration and management for mail services.
// Each email domain has its own authentication agent and message storage.
package domain

import (
	"errors"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
)

// Domain holds the configuration and agents for a single email domain.
type Domain struct {
	// Name is the domain name (e.g., "example.com").
	Name string

	// AuthAgent handles user authentication and existence checks for this domain.
	AuthAgent auth.AuthenticationAgent

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
