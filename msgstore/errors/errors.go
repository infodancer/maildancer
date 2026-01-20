// Package errors provides centralized error definitions for msgstore.
package errors

import "errors"

// Mailbox errors.
var (
	// ErrMailboxNotFound indicates the requested mailbox does not exist.
	ErrMailboxNotFound = errors.New("mailbox not found")

	// ErrMailboxLocked indicates the mailbox is locked by another operation.
	ErrMailboxLocked = errors.New("mailbox locked")
)

// Message errors.
var (
	// ErrMessageNotFound indicates the requested message does not exist.
	ErrMessageNotFound = errors.New("message not found")

	// ErrMessageDeleted indicates the message has been marked for deletion.
	ErrMessageDeleted = errors.New("message deleted")
)

// Delivery errors.
var (
	// ErrNoRecipients indicates no valid recipients were provided.
	ErrNoRecipients = errors.New("no recipients")

	// ErrRecipientNotFound indicates a recipient mailbox does not exist.
	ErrRecipientNotFound = errors.New("recipient not found")

	// ErrQuotaExceeded indicates the mailbox quota has been exceeded.
	ErrQuotaExceeded = errors.New("quota exceeded")
)

// Store errors.
var (
	// ErrStoreNotRegistered indicates the requested store type is not registered.
	ErrStoreNotRegistered = errors.New("store type not registered")

	// ErrStoreConfigInvalid indicates the store configuration is invalid.
	ErrStoreConfigInvalid = errors.New("invalid store configuration")
)

// Maildir errors.
var (
	// ErrMaildirNotFound indicates the maildir directory does not exist.
	ErrMaildirNotFound = errors.New("maildir not found")

	// ErrDeliveryFailed indicates message delivery failed.
	ErrDeliveryFailed = errors.New("delivery failed")

	// ErrInvalidPath indicates an invalid maildir path.
	ErrInvalidPath = errors.New("invalid maildir path")

	// ErrPathTraversal indicates an attempted path traversal attack.
	ErrPathTraversal = errors.New("path traversal rejected")
)
