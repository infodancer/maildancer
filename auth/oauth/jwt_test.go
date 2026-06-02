package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testKeySet holds a test RSA key pair and JWKS for testing
type testKeySet struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwkSet     jwk.Set
	keyID      string
}

func newTestKeySet(t *testing.T) *testKeySet {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyID := "test-key-1"

	// Create JWK from public key
	pubJWK, err := jwk.FromRaw(privateKey.Public())
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, keyID); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		t.Fatalf("failed to set key usage: %v", err)
	}

	keySet := jwk.NewSet()
	if err := keySet.AddKey(pubJWK); err != nil {
		t.Fatalf("failed to add key to set: %v", err)
	}

	return &testKeySet{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		jwkSet:     keySet,
		keyID:      keyID,
	}
}

func (ks *testKeySet) signToken(t *testing.T, token jwt.Token) string {
	t.Helper()

	// Create signing key
	signingKey, err := jwk.FromRaw(ks.privateKey)
	if err != nil {
		t.Fatalf("failed to create signing key: %v", err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, ks.keyID); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return string(signed)
}

func (ks *testKeySet) serveJWKS(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(ks.jwkSet)
		if err != nil {
			t.Errorf("failed to marshal JWKS: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	}))
}

func TestJWTAgent_ValidateToken_Success(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a valid token
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("email", "user@example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	username, err := agent.ValidateToken(ctx, signedToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if username != "user@example.com" {
		t.Errorf("expected username 'user@example.com', got %q", username)
	}
}

func TestJWTAgent_ValidateToken_ExpiredToken(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create an expired token
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("email", "user@example.com").
		IssuedAt(time.Now().Add(-2 * time.Hour)).
		Expiration(time.Now().Add(-1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	_, err = agent.ValidateToken(ctx, signedToken)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestJWTAgent_ValidateToken_WrongIssuer(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token with wrong issuer
	token, err := jwt.NewBuilder().
		Issuer("https://wrong-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("email", "user@example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	_, err = agent.ValidateToken(ctx, signedToken)
	if err != ErrIssuerMismatch {
		t.Errorf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestJWTAgent_ValidateToken_WrongAudience(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token with wrong audience
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"wrong-audience"}).
		Subject("user123").
		Claim("email", "user@example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	_, err = agent.ValidateToken(ctx, signedToken)
	if err != ErrAudienceMismatch {
		t.Errorf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestJWTAgent_ValidateToken_DomainRestriction(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:        server.URL,
		Issuer:         "https://test-issuer.example.com",
		Audience:       "smtp-server",
		UsernameClaim:  "email",
		AllowedDomains: []string{"allowed.com"},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token with disallowed domain
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("email", "user@notallowed.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	_, err = agent.ValidateToken(ctx, signedToken)
	if err != ErrDomainNotAllowed {
		t.Errorf("expected ErrDomainNotAllowed, got %v", err)
	}
}

func TestJWTAgent_ValidateToken_AllowedDomain(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:        server.URL,
		Issuer:         "https://test-issuer.example.com",
		Audience:       "smtp-server",
		UsernameClaim:  "email",
		AllowedDomains: []string{"allowed.com", "EXAMPLE.COM"},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token with allowed domain (case-insensitive)
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("email", "user@Example.Com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	username, err := agent.ValidateToken(ctx, signedToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if username != "user@Example.Com" {
		t.Errorf("expected username 'user@Example.Com', got %q", username)
	}
}

func TestJWTAgent_ValidateToken_FallbackClaim(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "custom_claim", // This claim won't exist
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token without custom_claim but with preferred_username
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		Subject("user123").
		Claim("preferred_username", "fallback@example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	username, err := agent.ValidateToken(ctx, signedToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if username != "fallback@example.com" {
		t.Errorf("expected username 'fallback@example.com', got %q", username)
	}
}

func TestJWTAgent_ValidateToken_MissingUsername(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "custom_claim",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Create a token without any username claims (not even sub)
	token, err := jwt.NewBuilder().
		Issuer("https://test-issuer.example.com").
		Audience([]string{"smtp-server"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	signedToken := ks.signToken(t, token)

	_, err = agent.ValidateToken(ctx, signedToken)
	if err != ErrUsernameMissing {
		t.Errorf("expected ErrUsernameMissing, got %v", err)
	}
}

func TestJWTAgent_InvalidToken(t *testing.T) {
	ks := newTestKeySet(t)
	server := ks.serveJWKS(t)
	defer server.Close()

	ctx := context.Background()

	agent, err := NewJWTAgent(ctx, JWTAgentConfig{
		JWKSURL:       server.URL,
		Issuer:        "https://test-issuer.example.com",
		Audience:      "smtp-server",
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	// Test with garbage token
	_, err = agent.ValidateToken(ctx, "not-a-valid-token")
	if err == nil {
		t.Error("expected error for invalid token, got nil")
	}
}

func TestNewJWTAgent_MissingConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		cfg     JWTAgentConfig
		wantErr string
	}{
		{
			name:    "missing JWKS URL",
			cfg:     JWTAgentConfig{Issuer: "iss", Audience: "aud"},
			wantErr: "JWKS URL is required",
		},
		{
			name:    "missing issuer",
			cfg:     JWTAgentConfig{JWKSURL: "http://example.com/jwks", Audience: "aud"},
			wantErr: "issuer is required",
		},
		{
			name:    "missing audience",
			cfg:     JWTAgentConfig{JWKSURL: "http://example.com/jwks", Issuer: "iss"},
			wantErr: "audience is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJWTAgent(ctx, tt.cfg)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestExtractDomainFromEmail(t *testing.T) {
	tests := []struct {
		email  string
		domain string
	}{
		{"user@example.com", "example.com"},
		{"user@sub.example.com", "sub.example.com"},
		{"user", ""},
		{"user@", ""},
		{"@example.com", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractDomainFromEmail(tt.email)
			if got != tt.domain {
				t.Errorf("extractDomainFromEmail(%q) = %q, want %q", tt.email, got, tt.domain)
			}
		})
	}
}
