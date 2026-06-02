package pop3

import "errors"

// Protocol errors for POP3.
var (
	// ErrInvalidState is returned when a command is not valid in the current state.
	ErrInvalidState = errors.New("command not valid in current state")

	// ErrTLSRequired is returned when authentication is attempted without TLS.
	ErrTLSRequired = errors.New("TLS required for authentication")

	// ErrTLSNotAvailable is returned when STLS is requested but TLS is not configured.
	ErrTLSNotAvailable = errors.New("TLS not available")

	// ErrAlreadyTLS is returned when STLS is requested on an already-encrypted connection.
	ErrAlreadyTLS = errors.New("already using TLS")

	// ErrNoUsername is returned when PASS is used before USER.
	ErrNoUsername = errors.New("username not specified")

	// ErrAuthFailed is returned when authentication fails.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrInvalidCommand is returned when a command is not recognized.
	ErrInvalidCommand = errors.New("invalid command")

	// ErrNoSuchMessage is returned when a message number doesn't exist.
	ErrNoSuchMessage = errors.New("no such message")

	// ErrMessageDeleted is returned when accessing a message marked for deletion.
	ErrMessageDeleted = errors.New("message already deleted")

	// ErrMailboxNotInitialized is returned when mailbox is accessed before auth.
	ErrMailboxNotInitialized = errors.New("mailbox not initialized")
)
