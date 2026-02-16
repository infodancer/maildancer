package domain

import (
	"context"
	"strings"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// AuthResult contains the authentication session and the resolved domain.
// Domain is nil when authentication was handled by the global fallback agent.
type AuthResult struct {
	Session *auth.AuthSession
	Domain  *Domain
}

// AuthRouter routes authentication requests to domain-specific agents or a
// global fallback. It implements auth.AuthenticationAgent so it can be used
// as a drop-in replacement anywhere an auth agent is expected.
//
// When a username contains an @ sign, the router splits it into local part
// and domain, looks up the domain via the provider, and authenticates the
// local part against the domain's auth agent. If no domain provider is
// configured, or the domain is not found, or the username has no @ sign,
// the router falls back to the global auth agent with the original username.
//
// Lifecycle: AuthRouter does not own the domain provider or fallback agent.
// The caller is responsible for closing them independently.
type AuthRouter struct {
	provider DomainProvider
	fallback auth.AuthenticationAgent
}

// NewAuthRouter creates a new AuthRouter. Both provider and fallback may be nil.
// If provider is nil, all requests go to the fallback.
// If fallback is nil, only domain-based authentication is available.
func NewAuthRouter(provider DomainProvider, fallback auth.AuthenticationAgent) *AuthRouter {
	return &AuthRouter{
		provider: provider,
		fallback: fallback,
	}
}

// SplitUsername splits "user@domain" into local part and domain.
// Returns the full username and empty domain if no @ is present.
func SplitUsername(username string) (localPart, domainName string) {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[:idx], username[idx+1:]
	}
	return username, ""
}

// Authenticate validates credentials, routing to domain-specific or fallback
// auth agents as appropriate. Implements auth.AuthenticationAgent.
func (r *AuthRouter) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	result, err := r.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return result.Session, nil
}

// AuthenticateWithDomain validates credentials and returns both the auth
// session and the resolved domain. Use this when the caller needs access
// to domain-specific resources (e.g., MessageStore for pop3d/imapd).
func (r *AuthRouter) AuthenticateWithDomain(ctx context.Context, username, password string) (*AuthResult, error) {
	localPart, domainName := SplitUsername(username)

	if r.provider != nil && domainName != "" {
		d := r.provider.GetDomain(domainName)
		if d != nil {
			session, err := d.AuthAgent.Authenticate(ctx, localPart, password)
			if err != nil {
				return nil, err
			}
			return &AuthResult{Session: session, Domain: d}, nil
		}
	}

	if r.fallback != nil {
		session, err := r.fallback.Authenticate(ctx, username, password)
		if err != nil {
			return nil, err
		}
		return &AuthResult{Session: session, Domain: nil}, nil
	}

	return nil, autherrors.ErrAuthFailed
}

// UserExists checks if a user exists, routing to domain-specific or fallback
// auth agents as appropriate. Implements auth.AuthenticationAgent.
func (r *AuthRouter) UserExists(ctx context.Context, username string) (bool, error) {
	localPart, domainName := SplitUsername(username)

	if r.provider != nil && domainName != "" {
		d := r.provider.GetDomain(domainName)
		if d != nil {
			return d.AuthAgent.UserExists(ctx, localPart)
		}
	}

	if r.fallback != nil {
		return r.fallback.UserExists(ctx, username)
	}

	return false, nil
}

// Close is a no-op. AuthRouter does not own the domain provider or fallback
// agent; the caller manages their lifecycles independently.
func (r *AuthRouter) Close() error {
	return nil
}
