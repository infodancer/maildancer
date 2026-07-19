package authoidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestForwardedProto_DiscoveryAndTokenIssuerMatch is the end-to-end regression
// guard for the incident behind #59: a reverse-proxy scheme bug shipped to
// production because issuerBase had no coverage beyond its own unit tests.
// It exercises the full request -> handler -> emitted doc/token wiring
// (serveDiscovery and the token path), not just the issuerBase helper, with
// X-Forwarded-Proto: https set on every request the way Traefik would. A
// silent scheme regression breaks federation cluster-wide: a conformant
// relying party rejects a non-https issuer or a token whose iss doesn't match
// the discovery document exactly.
func TestForwardedProto_DiscoveryAndTokenIssuerMatch(t *testing.T) {
	handler := newTestServer(t)
	wantIssuer := "https://" + testHost

	// --- discovery doc: every endpoint URL shares the forwarded scheme ---
	discReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	discReq.Host = testHost
	discReq.Header.Set("X-Forwarded-Proto", "https")
	discRR := httptest.NewRecorder()
	handler.ServeHTTP(discRR, discReq)
	if discRR.Code != http.StatusOK {
		t.Fatalf("discovery status = %d; body: %s", discRR.Code, discRR.Body)
	}
	var doc map[string]any
	if err := json.NewDecoder(discRR.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery doc: %v", err)
	}
	if doc["issuer"] != wantIssuer {
		t.Errorf("issuer = %v, want %s", doc["issuer"], wantIssuer)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		v, _ := doc[key].(string)
		if !strings.HasPrefix(v, wantIssuer) {
			t.Errorf("%s = %q, want prefix %q", key, v, wantIssuer)
		}
	}

	// --- full login + token exchange, all requests forwarded as https ---
	verifier, challenge := pkceParams()

	authorizeReq := httptest.NewRequest(http.MethodGet, authorizeURL("fp", challenge), nil)
	authorizeReq.Host = testHost
	authorizeReq.Header.Set("X-Forwarded-Proto", "https")
	authorizeRR := httptest.NewRecorder()
	handler.ServeHTTP(authorizeRR, authorizeReq)
	var csrfCookie *http.Cookie
	for _, c := range authorizeRR.Result().Cookies() {
		if c.Name == "auth_oidc_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("no CSRF cookie from authorize")
	}

	form := url.Values{}
	form.Set("csrf_token", csrfCookie.Value)
	form.Set("client_id", "testclient")
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("scope", "openid email")
	form.Set("state", "fp")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("username", "alice")
	form.Set("password", "s3cr3t")
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Host = testHost
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	loginReq.AddCookie(csrfCookie)
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusFound {
		t.Fatalf("login status = %d; body: %s", loginRR.Code, loginRR.Body)
	}
	loc, err := url.Parse(loginRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loginRR.Header().Get("Location"))
	}

	tf := url.Values{}
	tf.Set("grant_type", "authorization_code")
	tf.Set("code", code)
	tf.Set("redirect_uri", "https://app.example/callback")
	tf.Set("client_id", "testclient")
	tf.Set("code_verifier", verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tf.Encode()))
	tokenReq.Host = testHost
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("X-Forwarded-Proto", "https")
	tokenRR := httptest.NewRecorder()
	handler.ServeHTTP(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token status = %d; body: %s", tokenRR.Code, tokenRR.Body)
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(tokenRR.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	idToken, _ := tokenResp["id_token"].(string)
	if idToken == "" {
		t.Fatal("missing id_token")
	}

	// Verify the ID token's signature against the published JWKS and assert its
	// iss claim matches the discovery document's issuer exactly -- a
	// conformant relying party validates both and rejects a mismatch.
	jwksReq := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	jwksReq.Host = testHost
	jwksRR := httptest.NewRecorder()
	handler.ServeHTTP(jwksRR, jwksReq)
	set, err := jwk.Parse(jwksRR.Body.Bytes())
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	parsed, err := jwt.Parse([]byte(idToken), jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if parsed.Issuer() != wantIssuer {
		t.Errorf("id_token iss = %q, want %q", parsed.Issuer(), wantIssuer)
	}
}
