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
)

// Authentication agent errors.
var (
	// ErrAuthAgentNotRegistered indicates the requested auth agent type is not registered.
	ErrAuthAgentNotRegistered = errors.New("auth agent type not registered")

	// ErrAuthAgentConfigInvalid indicates the auth agent configuration is invalid.
	ErrAuthAgentConfigInvalid = errors.New("invalid auth agent configuration")

	// ErrKeyDecryptFailed indicates the private key could not be decrypted.
	ErrKeyDecryptFailed = errors.New("key decryption failed")

	// ErrKeyNotFound indicates the user's key file does not exist.
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidKeyFormat indicates the key file has an invalid format.
	ErrInvalidKeyFormat = errors.New("invalid key format")

	// ErrEncryptionNotEnabled indicates encryption is not enabled for the user.
	ErrEncryptionNotEnabled = errors.New("encryption not enabled")
)
