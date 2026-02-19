// Package errors defines sentinel errors for the IMAP server.
package errors

import "errors"

// Mailbox and session errors.
var (
	// ErrInvalidState is returned when a command is issued in the wrong session state.
	ErrInvalidState = errors.New("invalid state for command")

	// ErrNotAuthenticated is returned when a command requires authentication.
	ErrNotAuthenticated = errors.New("not authenticated")

	// ErrAlreadyAuthenticated is returned when attempting to authenticate again.
	ErrAlreadyAuthenticated = errors.New("already authenticated")

	// ErrNoMailboxSelected is returned when a command requires a selected mailbox.
	ErrNoMailboxSelected = errors.New("no mailbox selected")

	// ErrReadOnly is returned when a write operation is attempted on a read-only mailbox.
	ErrReadOnly = errors.New("mailbox is read-only")

	// ErrMailboxNotFound is returned when the named mailbox does not exist.
	ErrMailboxNotFound = errors.New("mailbox not found")
)

// TLS errors.
var (
	// ErrTLSRequired is returned when a command requires TLS but TLS is not active.
	ErrTLSRequired = errors.New("TLS required")

	// ErrTLSNotAvailable is returned when TLS is not configured on the server.
	ErrTLSNotAvailable = errors.New("TLS not available")

	// ErrAlreadyTLS is returned when attempting to start TLS on an already-TLS connection.
	ErrAlreadyTLS = errors.New("connection already using TLS")
)

// Authentication errors.
var (
	// ErrAuthFailed is returned when authentication credentials are invalid.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrAuthCancelled is returned when the client cancels an authentication exchange.
	ErrAuthCancelled = errors.New("authentication cancelled")
)

// Command errors.
var (
	// ErrInvalidCommand is returned when the command syntax is malformed.
	ErrInvalidCommand = errors.New("invalid command")

	// ErrInvalidArguments is returned when command arguments are invalid.
	ErrInvalidArguments = errors.New("invalid arguments")

	// ErrUnknownCommand is returned when the command is not recognised.
	ErrUnknownCommand = errors.New("unknown command")
)

// Message errors.
var (
	// ErrNoSuchMessage is returned when the specified message does not exist.
	ErrNoSuchMessage = errors.New("no such message")

	// ErrMessageDeleted is returned when operating on a message marked for deletion.
	ErrMessageDeleted = errors.New("message is deleted")
)

// Protocol errors.
var (
	// ErrLiteralTooLarge is returned when a client literal exceeds the server limit.
	ErrLiteralTooLarge = errors.New("literal too large")
)
