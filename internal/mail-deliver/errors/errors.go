// Package errors defines sentinel errors for mail-deliver.
package errors

import "errors"

var (
	// ErrNoRecipients is returned when a DeliverRequest contains no recipients.
	ErrNoRecipients = errors.New("no recipients in envelope")

	// ErrDomainNotFound is returned when the recipient's domain is not configured.
	ErrDomainNotFound = errors.New("recipient domain not configured")

	// ErrNoDeliveryAgent is returned when no delivery agent is available for the domain.
	ErrNoDeliveryAgent = errors.New("no delivery agent for recipient domain")

	// ErrMessageTooLarge is returned when the message body exceeds the size limit.
	ErrMessageTooLarge = errors.New("message too large")
)
