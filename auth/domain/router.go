package domain

import (
	"context"
	"log/slog"
	"strings"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/redis/go-redis/v9"
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

// WithRateLimit enables authentication rate limiting backed by an in-process
// store. State is not shared with other processes and does not survive a
// restart, so this is the fallback for deployments without Redis (and the
// path tests use). Prefer WithRedisRateLimit in production.
func (r *AuthRouter) WithRateLimit(cfg RateLimitConfig) *AuthRouter {
	r.rateLimiter = newAuthRateLimiter(cfg, newMemLimitStore())
	return r
}

// WithRedisRateLimit enables authentication rate limiting backed by Redis, so
// counters and lockouts are shared across every daemon and survive restarts
// (#206). The caller owns client's lifecycle.
//
// A nil client falls back to the in-process store rather than silently
// disabling rate limiting.
func (r *AuthRouter) WithRedisRateLimit(cfg RateLimitConfig, client *redis.Client) *AuthRouter {
	if client == nil {
		return r.WithRateLimit(cfg)
	}
	r.rateLimiter = newAuthRateLimiter(cfg, newRedisLimitStore(client))
	return r
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
// Rate limiting: if WithRateLimit or WithRedisRateLimit has been called, failed
// attempts are tracked by (IP, username) pair and by IP. Exceeding either
// threshold returns errors.ErrRateLimited. The client IP must be present in the
// context (see WithClientIP); without it there is no dimension to key on and no
// limiting happens.
func (r *AuthRouter) AuthenticateWithDomain(ctx context.Context, username, password string) (*AuthResult, error) {
	clientIP := clientIPFromContext(ctx)

	// Check rate limits before attempting authentication.
	if r.rateLimiter != nil && r.rateLimiter.isLimited(ctx, clientIP, username) {
		slog.Warn("auth rate limited", "username", username, "ip", clientIP)
		return nil, autherrors.ErrRateLimited
	}

	result, err := r.authenticateInternal(ctx, username, password)
	if err != nil {
		if r.rateLimiter != nil {
			r.rateLimiter.recordFailure(ctx, clientIP, username)
		}
		return nil, err
	}

	// Clear the (IP, username) pair on success.
	if r.rateLimiter != nil {
		r.rateLimiter.recordSuccess(ctx, clientIP, username)
	}
	return result, nil
}

// hasDomains reports whether the provider hosts any domains at all.
//
// This distinguishes "we host domains, just not that one" from "this is an
// unconfigured drop-in host", which are the two cases an unhosted domain can
// mean and which need opposite handling.
func (r *AuthRouter) hasDomains() bool {
	return r.provider != nil && len(r.provider.Domains()) > 0
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
		// The domain is not hosted here. On a server that hosts domains at all
		// that is a distinct signal, and reporting it as such is what stops a
		// migrated domain's stale clients from being banned on their first
		// attempt (#221).
		//
		// Gated on there being domains configured, because the fallback agent
		// exists for the legacy unqualified case -- old unix user@host, where
		// the host is implied. A server with no domains configured is exactly
		// that host and keeps its behaviour; a server with domains is not, so a
		// qualified username naming an unhosted domain never reaches the
		// fallback there.
		//
		// hasDomains costs a directory scan for the filesystem provider, so it
		// is deliberately the last thing checked: only an attempt that has
		// already named an unhosted domain pays for it, and that path is held
		// for auth_fail_delay anyway.
		if r.hasDomains() {
			return nil, autherrors.ErrDomainNotHosted
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

// Close releases router-owned resources. It is currently a no-op: the rate
// limiter's expiry is TTL-based, so there is no longer a cleanup goroutine to
// stop, and the Redis client belongs to the caller. It is retained because
// callers already defer it and a future owned resource would need it back.
//
// AuthRouter does not own the domain provider or fallback agent; the caller
// manages their lifecycles independently.
func (r *AuthRouter) Close() error {
	return nil
}
