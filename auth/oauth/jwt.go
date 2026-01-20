package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JWTAgent validates JWT bearer tokens using JWKS.
type JWTAgent struct {
	keySet         jwk.Set
	cache          *jwk.Cache
	jwksURL        string
	issuer         string
	audience       string
	usernameClaim  string
	allowedDomains map[string]bool
}

// JWTAgentConfig holds configuration for creating a JWTAgent.
type JWTAgentConfig struct {
	JWKSURL         string
	Issuer          string
	Audience        string
	UsernameClaim   string
	RefreshInterval time.Duration
	AllowedDomains  []string
}

// NewJWTAgent creates a new JWT validation agent.
// It fetches the JWKS from the provided URL and sets up automatic refresh.
func NewJWTAgent(ctx context.Context, cfg JWTAgentConfig) (*JWTAgent, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}

	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "email"
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 1 * time.Hour
	}

	// Create JWKS cache with auto-refresh
	cache := jwk.NewCache(ctx)
	if err := cache.Register(cfg.JWKSURL, jwk.WithMinRefreshInterval(cfg.RefreshInterval)); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Fetch initial key set
	keySet, err := cache.Refresh(ctx, cfg.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Build allowed domains map
	allowedDomains := make(map[string]bool)
	for _, d := range cfg.AllowedDomains {
		allowedDomains[strings.ToLower(d)] = true
	}

	return &JWTAgent{
		keySet:         keySet,
		cache:          cache,
		jwksURL:        cfg.JWKSURL,
		issuer:         cfg.Issuer,
		audience:       cfg.Audience,
		usernameClaim:  cfg.UsernameClaim,
		allowedDomains: allowedDomains,
	}, nil
}

// ValidateToken validates a JWT bearer token and returns the authenticated username.
func (a *JWTAgent) ValidateToken(ctx context.Context, token string) (string, error) {
	// Get current key set (may be refreshed from cache)
	keySet, err := a.cache.Get(ctx, a.jwksURL)
	if err != nil {
		// Fall back to initial key set if cache fetch fails
		keySet = a.keySet
	}

	// Parse and validate the token
	parsedToken, err := jwt.Parse(
		[]byte(token),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
	)
	if err != nil {
		errStr := err.Error()
		// Check for specific validation errors
		if strings.Contains(errStr, `"exp"`) && strings.Contains(errStr, "not satisfied") {
			return "", ErrTokenExpired
		}
		if strings.Contains(errStr, `"iss"`) && strings.Contains(errStr, "not satisfied") {
			return "", ErrIssuerMismatch
		}
		if strings.Contains(errStr, `"aud"`) && strings.Contains(errStr, "not satisfied") {
			return "", ErrAudienceMismatch
		}
		return "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// Extract username from the configured claim
	username, err := a.extractUsername(parsedToken)
	if err != nil {
		return "", err
	}

	// Check domain restriction
	if len(a.allowedDomains) > 0 {
		domain := extractDomainFromEmail(username)
		if domain == "" || !a.allowedDomains[strings.ToLower(domain)] {
			return "", ErrDomainNotAllowed
		}
	}

	return username, nil
}

// extractUsername extracts the username from the token based on the configured claim.
func (a *JWTAgent) extractUsername(token jwt.Token) (string, error) {
	// Try the configured claim first
	if val, ok := token.Get(a.usernameClaim); ok {
		if username, ok := val.(string); ok && username != "" {
			return username, nil
		}
	}

	// Fall back to common claims if the configured one is not found
	fallbackClaims := []string{"email", "preferred_username", "upn", "sub"}
	for _, claim := range fallbackClaims {
		if claim == a.usernameClaim {
			continue // Already tried this one
		}
		if val, ok := token.Get(claim); ok {
			if username, ok := val.(string); ok && username != "" {
				return username, nil
			}
		}
	}

	return "", ErrUsernameMissing
}

// Close releases resources held by the agent.
func (a *JWTAgent) Close() error {
	// The cache will be garbage collected when the context used to create it is cancelled.
	// No explicit cleanup needed.
	return nil
}

// extractDomainFromEmail extracts the domain part from an email address.
func extractDomainFromEmail(email string) string {
	idx := strings.LastIndex(email, "@")
	if idx < 0 || idx == len(email)-1 {
		return ""
	}
	return email[idx+1:]
}
