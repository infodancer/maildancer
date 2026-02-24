// Package errors defines centralized error types for the webadmin module.
package errors

import "errors"

var (
	// ErrUnauthorized indicates the request lacks valid authentication.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates the authenticated user lacks permission.
	ErrForbidden = errors.New("forbidden")

	// ErrInvalidConfig indicates a configuration error.
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrSessionExpired indicates the session has timed out.
	ErrSessionExpired = errors.New("session expired")

	// ErrCSRFValidation indicates a CSRF token mismatch.
	ErrCSRFValidation = errors.New("CSRF validation failed")

	// ErrInvalidDomainName indicates a domain name that fails validation.
	ErrInvalidDomainName = errors.New("invalid domain name")

	// ErrInvalidUsername indicates a username that fails validation.
	ErrInvalidUsername = errors.New("invalid username")

	// ErrDomainExists indicates the domain already exists.
	ErrDomainExists = errors.New("domain already exists")

	// ErrDomainNotFound indicates the domain was not found.
	ErrDomainNotFound = errors.New("domain not found")

	// ErrUserExists indicates the user already exists in the domain.
	ErrUserExists = errors.New("user already exists")

	// ErrUserNotFound indicates the user was not found in the domain.
	ErrUserNotFound = errors.New("user not found")

	// ErrPasswordTooWeak indicates the password does not meet complexity requirements.
	ErrPasswordTooWeak = errors.New("password does not meet complexity requirements")
)
