package domain

import (
	"context"
	"log/slog"
	"strings"
	"time"

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
	provider    DomainProvider
	fallback    auth.AuthenticationAgent
	rateLimiter *authRateLimiter
	cleanupDone chan struct{} // closed to stop the cleanup goroutine
}

// NewAuthRouter creates a new AuthRouter with no rate limiting.
// Both provider and fallback may be nil.
// If provider is nil, all requests go to the fallback.
// If fallback is nil, only domain-based authentication is available.
// Use WithRateLimit to enable rate limiting.
func NewAuthRouter(provider DomainProvider, fallback auth.AuthenticationAgent) *AuthRouter {
	return &AuthRouter{
		provider: provider,
		fallback: fallback,
	}
}

// WithRateLimit enables authentication rate limiting on the router.
// Starts a background cleanup goroutine; call Close() to stop it.
func (r *AuthRouter) WithRateLimit(cfg RateLimitConfig) *AuthRouter {
	r.rateLimiter = newAuthRateLimiter(cfg)
	r.cleanupDone = make(chan struct{})
	go r.cleanupLoop()
	return r
}

// cleanupLoop periodically removes expired rate limit entries.
func (r *AuthRouter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.rateLimiter.cleanup()
		case <-r.cleanupDone:
			return
		}
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
//
// Rate limiting: if WithRateLimit has been called, failed attempts are tracked
// by client IP (from context, see WithClientIP), username, and (IP, username)
// pair. Exceeding any threshold returns errors.ErrRateLimited.
func (r *AuthRouter) AuthenticateWithDomain(ctx context.Context, username, password string) (*AuthResult, error) {
	clientIP := clientIPFromContext(ctx)

	// Check rate limits before attempting authentication.
	if r.rateLimiter != nil && r.rateLimiter.isLimited(clientIP, username) {
		slog.Warn("auth rate limited", "username", username, "ip", clientIP)
		return nil, autherrors.ErrRateLimited
	}

	result, err := r.authenticateInternal(ctx, username, password)
	if err != nil {
		if r.rateLimiter != nil {
			r.rateLimiter.recordFailure(clientIP, username)
		}
		return nil, err
	}

	// Clear the (IP, username) pair on success.
	if r.rateLimiter != nil {
		r.rateLimiter.recordSuccess(clientIP, username)
	}
	return result, nil
}

// authenticateInternal performs the actual credential check without rate limiting.
func (r *AuthRouter) authenticateInternal(ctx context.Context, username, password string) (*AuthResult, error) {
	localPart, domainName := SplitUsername(username)
	base, extension := ParseLocalPart(localPart)

	if r.provider != nil && domainName != "" {
		d := r.provider.GetDomain(domainName)
		if d != nil {
			session, err := d.AuthAgent.Authenticate(ctx, base, password)
			if err != nil {
				return nil, err
			}
			if session.User != nil {
				session.User.Mailbox = base + "@" + domainName
			}
			return &AuthResult{Session: session, Domain: d, Extension: extension}, nil
		}
	}

	if r.fallback != nil {
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

// Close stops the rate limit cleanup goroutine (if running). AuthRouter does
// not own the domain provider or fallback agent; the caller manages their
// lifecycles independently.
func (r *AuthRouter) Close() error {
	if r.cleanupDone != nil {
		close(r.cleanupDone)
	}
	return nil
}
