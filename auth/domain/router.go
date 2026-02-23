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
	Session   *auth.AuthSession
	Domain    *Domain
	Extension string // subaddress extension from "user+ext@domain", empty if none
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

// ParseLocalPart splits a local part on the first '+' into base and extension.
// "user+folder" → ("user", "folder")
// "user"        → ("user", "")
// "user+"       → ("user", "")
// "user+a+b"   → ("user", "a+b")
func ParseLocalPart(localPart string) (base, extension string) {
	if b, ext, ok := strings.Cut(localPart, "+"); ok {
		return b, ext
	}
	return localPart, ""
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
	base, extension := ParseLocalPart(localPart)

	if r.provider != nil && domainName != "" {
		d := r.provider.GetDomain(domainName)
		if d != nil {
			session, err := d.AuthAgent.Authenticate(ctx, base, password)
			if err != nil {
				return nil, err
			}
			// Normalize Mailbox to the canonical localpart.
			// Auth agents receive only the localpart and may set Mailbox to that
			// value or leave it empty. Normalizing here ensures pop3d/imapd always
			// open the same mailbox path as smtpd delivers to. The domain is already
			// encoded in the per-domain msgstore base_path, so the localpart is the
			// correct key into the message store (matching path_template = "{localpart}").
			if session.User != nil {
				session.User.Mailbox = base
			}
			return &AuthResult{Session: session, Domain: d, Extension: extension}, nil
		}
	}

	if r.fallback != nil {
		// Fallback receives the full username but with the extension stripped
		// from the local part: "base@domain" or just "base" for bare usernames.
		fallbackUser := username
		if extension != "" {
			if domainName != "" {
				fallbackUser = base + "@" + domainName
			} else {
				fallbackUser = base
			}
		}
		session, err := r.fallback.Authenticate(ctx, fallbackUser, password)
		if err != nil {
			return nil, err
		}
		return &AuthResult{Session: session, Domain: nil, Extension: extension}, nil
	}

	return nil, autherrors.ErrAuthFailed
}

// UserExists checks if a user exists, routing to domain-specific or fallback
// auth agents as appropriate. Implements auth.AuthenticationAgent.
func (r *AuthRouter) UserExists(ctx context.Context, username string) (bool, error) {
	localPart, domainName := SplitUsername(username)
	base, extension := ParseLocalPart(localPart)

	if r.provider != nil && domainName != "" {
		d := r.provider.GetDomain(domainName)
		if d != nil {
			return d.AuthAgent.UserExists(ctx, base)
		}
	}

	if r.fallback != nil {
		// Strip extension from the fallback username too.
		fallbackUser := username
		if extension != "" {
			if domainName != "" {
				fallbackUser = base + "@" + domainName
			} else {
				fallbackUser = base
			}
		}
		return r.fallback.UserExists(ctx, fallbackUser)
	}

	return false, nil
}

// Close is a no-op. AuthRouter does not own the domain provider or fallback
// agent; the caller manages their lifecycles independently.
func (r *AuthRouter) Close() error {
	return nil
}
