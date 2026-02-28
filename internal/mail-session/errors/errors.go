// Package errors defines sentinel errors for the mail-session binary.
package errors

import "errors"

// ErrMailboxNotOpen is returned when a command requires an open mailbox but none is selected.
var ErrMailboxNotOpen = errors.New("no mailbox open")

// ErrMessageNotFound is returned when a UID does not exist in the current mailbox.
var ErrMessageNotFound = errors.New("message not found")

// ErrAlreadyDeleted is returned when Delete is called on a message already marked for deletion.
var ErrAlreadyDeleted = errors.New("message already marked for deletion")

// ErrNotDeleted is returned when Undelete is called on a message not marked for deletion.
var ErrNotDeleted = errors.New("message not marked for deletion")
