// Package oauth provides OAuth 2.0 bearer token validation for SMTP authentication.
package oauth

import (
	"context"
	"errors"
)

// Common errors returned by OAuthAgent implementations.
var (
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenInvalid     = errors.New("token invalid")
	ErrTokenMalformed   = errors.New("token malformed")
	ErrIssuerMismatch   = errors.New("issuer mismatch")
	ErrAudienceMismatch = errors.New("audience mismatch")
	ErrDomainNotAllowed = errors.New("domain not allowed")
	ErrUsernameMissing  = errors.New("username claim missing")
)

// Agent validates OAuth 2.0 bearer tokens and extracts the authenticated username.
type Agent interface {
	// ValidateToken validates an OAuth bearer token and returns the authenticated username.
	// Returns an error if the token is invalid, expired, or doesn't meet validation requirements.
	ValidateToken(ctx context.Context, token string) (username string, err error)

	// Close releases any resources held by the agent.
	Close() error
}
