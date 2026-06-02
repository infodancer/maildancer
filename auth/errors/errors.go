// Package errors provides centralized error definitions for auth.
package errors

import "errors"

// Authentication errors.
var (
	// ErrAuthFailed indicates authentication credentials are invalid.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrUserNotFound indicates the requested user does not exist.
	ErrUserNotFound = errors.New("user not found")

	// ErrRateLimited indicates too many failed authentication attempts.
	// Callers should return a temporary failure (e.g., SMTP 421) rather
	// than a credentials-invalid response.
	ErrRateLimited = errors.New("too many failed authentication attempts")
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
