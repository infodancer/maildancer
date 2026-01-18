// Package errors provides centralized error definitions for msgstore.
package errors

import "errors"

// Authentication errors.
var (
	// ErrAuthFailed indicates authentication credentials are invalid.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrUserNotFound indicates the requested user does not exist.
	ErrUserNotFound = errors.New("user not found")
)

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
