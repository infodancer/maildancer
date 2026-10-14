package authoidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// The address a passwd-backed account signs in with is the mailbox this
// server authenticated, so the IdP asserts email_verified for it. Relying
// parties that gate on the claim (as OIDC Core 5.1 lets them) refuse an ID
// token without it.
func TestIDToken_EmailVerified(t *testing.T) {
	handler := newTestServer(t)
	resp := fullLoginFlow(t, handler)
	idToken, _ := resp["id_token"].(string)
	if idToken == "" {
		t.Fatal("missing id_token")
	}

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
	if email, _ := parsed.Get("email"); email != "alice@test.example" {
		t.Errorf("id_token email = %v, want alice@test.example", email)
	}
	if v, ok := parsed.Get("email_verified"); !ok || v != true {
		t.Errorf("id_token email_verified = %v (present %v), want true", v, ok)
	}
}

func TestUserinfo_EmailVerified(t *testing.T) {
	handler := newTestServer(t)
	resp := fullLoginFlow(t, handler)
	accessToken, _ := resp["access_token"].(string)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d; body: %s", rr.Code, rr.Body)
	}
	var claims map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if claims["email_verified"] != true {
		t.Errorf("userinfo email_verified = %v, want true", claims["email_verified"])
	}
}

func TestDiscovery_ClaimsSupportedEmailVerified(t *testing.T) {
	handler := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = testHost
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var doc struct {
		ClaimsSupported []string `json:"claims_supported"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range doc.ClaimsSupported {
		if c == "email_verified" {
			return
		}
	}
	t.Errorf("claims_supported = %v, want email_verified listed", doc.ClaimsSupported)
}
