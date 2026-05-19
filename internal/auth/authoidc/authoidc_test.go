package authoidc_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/auth/authoidc"
	"github.com/infodancer/maildancer/auth/passwd"
)

const testHost = "auth.test.example" // resolves → "test.example" via label-strip

// newTestServer creates a Server wired to a temp directory with a test passwd
// file containing user "alice" with password "s3cr3t".
func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	domainDir := filepath.Join(tmpDir, "domains", "test.example")
	keyDir := filepath.Join(domainDir, "keys")

	for _, d := range []string{dataDir, domainDir, keyDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Write a minimal domain config.
	domainCfg := "[auth]\ntype = \"passwd\"\ncredential_backend = \"passwd\"\nkey_backend = \"keys\"\n"
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(domainCfg), 0600); err != nil {
		t.Fatalf("write domain config: %v", err)
	}

	passwdPath := filepath.Join(domainDir, "passwd")
	if err := passwd.AddUser(passwdPath, "alice", "s3cr3t"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	cfg := &authoidc.Config{
		Server: authoidc.ServerConfig{
			Listen:         ":0",
			DataDir:        dataDir,
			DomainDataPath: filepath.Join(tmpDir, "domains"),
			JWTTTLSec:      3600,
			SessionTTLSec:  604800,
		},
		Clients: []authoidc.ClientConfig{
			{
				Domain:       "test.example",
				ID:           "testclient",
				Secret:       "",
				RedirectURIs: []string{"https://app.example/callback"},
			},
		},
	}

	srv, err := authoidc.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv.Handler()
}

// pkceParams generates a PKCE verifier/challenge pair.
func pkceParams() (verifier, challenge string) {
	verifier = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("x"), 32))
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func authorizeURL(state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "testclient")
	q.Set("redirect_uri", "https://app.example/callback")
	q.Set("scope", "openid email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return "/authorize?" + q.Encode()
}

func TestHealthz(t *testing.T) {
	handler := newTestServer(t)
	rr := doRequest(handler, http.MethodGet, "/healthz", nil, nil)
	if rr.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", rr.Code)
	}
}

func TestDiscovery(t *testing.T) {
	handler := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = testHost
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantIssuer := "http://" + testHost
	if doc["issuer"] != wantIssuer {
		t.Errorf("issuer = %v, want %s", doc["issuer"], wantIssuer)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if doc[key] == nil {
			t.Errorf("missing %s", key)
		}
	}
}

func TestJWKS(t *testing.T) {
	handler := newTestServer(t)
	rr := doRequest(handler, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var jwks map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}
}

func TestAuthorize_ShowsLoginForm(t *testing.T) {
	handler := newTestServer(t)
	_, challenge := pkceParams()
	rr := doRequest(handler, http.MethodGet, authorizeURL("s", challenge), nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "Sign in") {
		t.Error("expected login form in response")
	}
}

func TestAuthorize_UnknownDomain(t *testing.T) {
	handler := newTestServer(t)
	_, challenge := pkceParams()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "testclient")
	q.Set("redirect_uri", "https://app.example/callback")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	req.Host = "auth.unknown.example" // no registered domain in the strip chain
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestAuthorize_MissingPKCE(t *testing.T) {
	handler := newTestServer(t)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "testclient")
	q.Set("redirect_uri", "https://app.example/callback")
	rr := doRequest(handler, http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestFullLoginFlow(t *testing.T) {
	handler := newTestServer(t)
	resp := fullLoginFlow(t, handler)

	for _, key := range []string{"access_token", "id_token"} {
		if v, _ := resp[key].(string); v == "" {
			t.Errorf("missing or empty %s", key)
		}
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
}

func TestUserinfo(t *testing.T) {
	handler := newTestServer(t)
	resp := fullLoginFlow(t, handler)

	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("no access_token")
	}

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
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", claims["sub"])
	}
	if claims["email"] != "alice@test.example" {
		t.Errorf("email = %v, want alice@test.example", claims["email"])
	}
}

func TestUserinfo_NoToken(t *testing.T) {
	handler := newTestServer(t)
	rr := doRequest(handler, http.MethodGet, "/userinfo", nil, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("userinfo without token = %d, want 401", rr.Code)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	handler := newTestServer(t)
	_, challenge := pkceParams()

	csrfToken, csrfCookie := getCSRF(t, handler, authorizeURL("s", challenge))

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("client_id", "testclient")
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("username", "alice")
	form.Set("password", "wrongpassword")

	rr := doRequest(handler, http.MethodPost, "/login",
		strings.NewReader(form.Encode()), []*http.Cookie{csrfCookie})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestToken_ReplayPrevented(t *testing.T) {
	handler := newTestServer(t)
	verifier, challenge := pkceParams()

	csrfToken, csrfCookie := getCSRF(t, handler, authorizeURL("s", challenge))
	code := doLogin(t, handler, csrfToken, csrfCookie, challenge, "alice", "s3cr3t")

	exchange := func() int {
		tf := url.Values{}
		tf.Set("grant_type", "authorization_code")
		tf.Set("code", code)
		tf.Set("redirect_uri", "https://app.example/callback")
		tf.Set("client_id", "testclient")
		tf.Set("code_verifier", verifier)
		rr := doRequest(handler, http.MethodPost, "/token",
			strings.NewReader(tf.Encode()), nil)
		return rr.Code
	}

	if first := exchange(); first != http.StatusOK {
		t.Fatalf("first exchange: %d", first)
	}
	if second := exchange(); second != http.StatusUnauthorized {
		t.Errorf("replay exchange: %d, want 401", second)
	}
}

func TestToken_BadPKCE(t *testing.T) {
	handler := newTestServer(t)
	_, challenge := pkceParams()

	csrfToken, csrfCookie := getCSRF(t, handler, authorizeURL("s", challenge))
	code := doLogin(t, handler, csrfToken, csrfCookie, challenge, "alice", "s3cr3t")

	tf := url.Values{}
	tf.Set("grant_type", "authorization_code")
	tf.Set("code", code)
	tf.Set("redirect_uri", "https://app.example/callback")
	tf.Set("client_id", "testclient")
	tf.Set("code_verifier", "wrong-verifier")
	rr := doRequest(handler, http.MethodPost, "/token",
		strings.NewReader(tf.Encode()), nil)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad PKCE: %d, want 400", rr.Code)
	}
}

func TestSSOSession(t *testing.T) {
	handler := newTestServer(t)
	_, challenge := pkceParams()

	csrfToken, csrfCookie := getCSRF(t, handler, authorizeURL("s1", challenge))
	loginRR := doLoginRaw(t, handler, csrfToken, csrfCookie, challenge, "alice", "s3cr3t")
	if loginRR.Code != http.StatusFound {
		t.Fatalf("login = %d", loginRR.Code)
	}

	var sessCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "auth_oidc_session" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("no session cookie after login")
	}

	// Second authorize with session cookie — should bypass login form.
	_, challenge2 := pkceParams()
	req := httptest.NewRequest(http.MethodGet, authorizeURL("s2", challenge2), nil)
	req.Host = testHost
	req.AddCookie(sessCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("SSO authorize = %d, want 302 (direct code redirect)", rr.Code)
	}
}

func TestLogout(t *testing.T) {
	handler := newTestServer(t)
	rr := doRequest(handler, http.MethodPost, "/logout", nil, nil)
	if rr.Code != http.StatusNoContent {
		t.Errorf("logout = %d, want 204", rr.Code)
	}
}

// --- RFC 7591 dynamic client registration ---

func TestRegister_Success(t *testing.T) {
	handler := newTestServer(t)
	body := `{"client_name":"myapp","redirect_uris":["https://app.test.example/cb"]}`
	rr := doRegisterRequest(handler, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register = %d; body: %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["client_id"] == "" {
		t.Error("expected non-empty client_id")
	}
	if resp["client_id_issued_at"] == nil {
		t.Error("expected client_id_issued_at")
	}
}

// TestRegister_ThirdPartyDomain verifies that any HTTPS redirect URI is accepted,
// regardless of whether the host is an infodancer domain. This is required to
// support "Login with infodancer.net" for third-party apps.
func TestRegister_ThirdPartyDomain(t *testing.T) {
	handler := newTestServer(t)
	body := `{"client_name":"thirdparty","redirect_uris":["https://someapp.example.com/callback"]}`
	rr := doRegisterRequest(handler, body)
	if rr.Code != http.StatusCreated {
		t.Errorf("third-party HTTPS URI: got %d, want 201; body: %s", rr.Code, rr.Body)
	}
}

// TestRegister_HTTPRedirectURI verifies that plain HTTP redirect URIs are rejected
// (except for localhost, which is allowed for local development).
func TestRegister_HTTPRedirectURI(t *testing.T) {
	handler := newTestServer(t)
	body := `{"redirect_uris":["http://app.test.example/cb"]}`
	rr := doRegisterRequest(handler, body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("HTTP URI: got %d, want 400", rr.Code)
	}
}

// TestRegister_LocalhostHTTP verifies that http://localhost is accepted for local dev.
func TestRegister_LocalhostHTTP(t *testing.T) {
	handler := newTestServer(t)
	body := `{"redirect_uris":["http://localhost:8080/cb"]}`
	rr := doRegisterRequest(handler, body)
	if rr.Code != http.StatusCreated {
		t.Errorf("localhost HTTP URI: got %d, want 201; body: %s", rr.Code, rr.Body)
	}
}

// TestRegister_NotIdempotent verifies that two registrations with identical payloads
// produce different client_ids, since IDs are now randomly generated (not HMAC-derived).
func TestRegister_NotIdempotent(t *testing.T) {
	handler := newTestServer(t)
	body := `{"client_name":"myapp","redirect_uris":["https://app.test.example/cb"]}`
	rr1 := doRegisterRequest(handler, body)
	rr2 := doRegisterRequest(handler, body)
	if rr1.Code != http.StatusCreated || rr2.Code != http.StatusCreated {
		t.Fatalf("register status: %d, %d", rr1.Code, rr2.Code)
	}
	var r1, r2 map[string]any
	_ = json.NewDecoder(rr1.Body).Decode(&r1)
	_ = json.NewDecoder(rr2.Body).Decode(&r2)
	if r1["client_id"] == r2["client_id"] {
		t.Errorf("expected different client_ids for repeated registration, got same: %v", r1["client_id"])
	}
}

// TestRegister_IPv6LoopbackHTTP verifies that http://[::1] is accepted for local dev.
func TestRegister_IPv6LoopbackHTTP(t *testing.T) {
	handler := newTestServer(t)
	body := `{"redirect_uris":["http://[::1]:8080/cb"]}`
	rr := doRegisterRequest(handler, body)
	if rr.Code != http.StatusCreated {
		t.Errorf("IPv6 loopback HTTP URI: got %d, want 201; body: %s", rr.Code, rr.Body)
	}
}

func TestDiscovery_RegistrationEndpoint(t *testing.T) {
	handler := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = testHost
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ep, _ := doc["registration_endpoint"].(string)
	if ep == "" {
		t.Error("expected registration_endpoint in discovery doc")
	}
}

func TestFullLoginFlow_DynamicClient(t *testing.T) {
	handler := newTestServer(t)

	// Register a client dynamically.
	regBody := `{"client_name":"dynapp","redirect_uris":["https://dynapp.test.example/callback"]}`
	regRR := doRegisterRequest(handler, regBody)
	if regRR.Code != http.StatusCreated {
		t.Fatalf("register = %d; body: %s", regRR.Code, regRR.Body)
	}
	var regResp map[string]any
	if err := json.NewDecoder(regRR.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	clientID, _ := regResp["client_id"].(string)
	if clientID == "" {
		t.Fatal("no client_id in registration response")
	}
	redirectURI := "https://dynapp.test.example/callback"

	verifier, challenge := pkceParams()

	// Authorize.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "st")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	csrfToken, csrfCookie := getCSRF(t, handler, "/authorize?"+q.Encode())

	// Login.
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("scope", "openid email")
	form.Set("state", "st")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("username", "alice")
	form.Set("password", "s3cr3t")
	loginRR := doRequest(handler, http.MethodPost, "/login",
		strings.NewReader(form.Encode()), []*http.Cookie{csrfCookie})
	if loginRR.Code != http.StatusFound {
		t.Fatalf("login = %d; body: %s", loginRR.Code, loginRR.Body)
	}
	loc := loginRR.Header().Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}

	// Token exchange.
	tf := url.Values{}
	tf.Set("grant_type", "authorization_code")
	tf.Set("code", code)
	tf.Set("redirect_uri", redirectURI)
	tf.Set("client_id", clientID)
	tf.Set("code_verifier", verifier)
	rr := doRequest(handler, http.MethodPost, "/token",
		strings.NewReader(tf.Encode()), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token = %d; body: %s", rr.Code, rr.Body)
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if at, _ := tokenResp["access_token"].(string); at == "" {
		t.Error("missing access_token")
	}
}

// --- flow helpers ---

// fullLoginFlow runs a complete authorize → login → token exchange for alice.
func fullLoginFlow(t *testing.T, handler http.Handler) map[string]any {
	t.Helper()
	verifier, challenge := pkceParams()

	csrfToken, csrfCookie := getCSRF(t, handler, authorizeURL("st1", challenge))
	code := doLogin(t, handler, csrfToken, csrfCookie, challenge, "alice", "s3cr3t")

	tf := url.Values{}
	tf.Set("grant_type", "authorization_code")
	tf.Set("code", code)
	tf.Set("redirect_uri", "https://app.example/callback")
	tf.Set("client_id", "testclient")
	tf.Set("code_verifier", verifier)
	rr := doRequest(handler, http.MethodPost, "/token",
		strings.NewReader(tf.Encode()), nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("token status = %d; body: %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp
}

// getCSRF performs a GET to target and returns the CSRF token + cookie.
func getCSRF(t *testing.T, handler http.Handler, target string) (token string, cookie *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = testHost
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == "auth_oidc_csrf" {
			return c.Value, c
		}
	}
	t.Fatal("no CSRF cookie from authorize")
	return "", nil
}

// doLogin submits the login form and returns the auth code from the redirect.
func doLogin(t *testing.T, handler http.Handler, csrfToken string, csrfCookie *http.Cookie, challenge, username, password string) string {
	t.Helper()
	rr := doLoginRaw(t, handler, csrfToken, csrfCookie, challenge, username, password)
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d; body: %s", rr.Code, rr.Body)
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}
	return code
}

func doLoginRaw(t *testing.T, handler http.Handler, csrfToken string, csrfCookie *http.Cookie, challenge, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("client_id", "testclient")
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("scope", "openid email")
	form.Set("state", "s")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("username", username)
	form.Set("password", password)
	return doRequest(handler, http.MethodPost, "/login",
		strings.NewReader(form.Encode()), []*http.Cookie{csrfCookie})
}

// doRegisterRequest sends a POST /register with a JSON body.
func doRegisterRequest(handler http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func doRequest(handler http.Handler, method, target string, body *strings.Reader, cookies []*http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Host = testHost
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}
