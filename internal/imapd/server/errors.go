package server

import "errors"

var (
	// ErrAlreadyTLS is returned when attempting to upgrade an already-TLS connection.
	ErrAlreadyTLS = errors.New("connection already using TLS")
)
