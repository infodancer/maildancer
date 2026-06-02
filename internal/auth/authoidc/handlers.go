package authoidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Registration input limits. RFC 7591 places no hard caps, but auth-oidc
// hashes the inputs to derive a stable client_id, so unbounded inputs would
// let a caller force arbitrarily large work per request. These limits make
// the implicit caps explicit and well under the size of any legitimate
// registration.
const (
	maxClientNameLen      = 200
	maxRedirectURIsPerReg = 10
	maxRedirectURILen     = 2048
)

const picoCSS = `https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css`

const sessionCookieName = "auth_oidc_session"
const csrfCookieName = "auth_oidc_csrf"

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in — {{.Domain}}</title>
  <link rel="stylesheet" href="` + picoCSS + `">
  <style>main{margin-top:4rem}</style>
</head>
<body>
<main class="container" style="max-width:480px">
  <article>
    <header><h2>Sign in to {{.Domain}}</h2></header>
    {{if .Error}}<p style="color:var(--pico-color-red-500)">{{.Error}}</p>{{end}}
    <form method="POST" action="{{.LoginAction}}">
      <input type="hidden" name="csrf_token"            value="{{.CSRFToken}}">
      <input type="hidden" name="client_id"             value="{{.ClientID}}">
      <input type="hidden" name="redirect_uri"          value="{{.RedirectURI}}">
      <input type="hidden" name="scope"                 value="{{.Scope}}">
      <input type="hidden" name="state"                 value="{{.State}}">
      <input type="hidden" name="code_challenge"        value="{{.CodeChallenge}}">
      <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
      <input type="hidden" name="nonce"                 value="{{.Nonce}}">
      <label>Email or username
        <input type="text" name="username" value="{{.Username}}" autofocus required autocomplete="username">
      </label>
      <label>Password
        <input type="password" name="password" required autocomplete="current-password">
      </label>
      <button type="submit">Sign in</button>
    </form>
  </article>
</main>
</body>
</html>`))

var errorTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <link rel="stylesheet" href="` + picoCSS + `">
  <style>main{margin-top:4rem}</style>
</head>
<body>
<main class="container" style="max-width:480px">
  <article>
    <header><h2>{{.Title}}</h2></header>
    <p>{{.Message}}</p>
  </article>
</main>
</body>
</html>`))

type loginFormData struct {
	Domain              string
	LoginAction         string // form POST action URL
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Username            string
	Error               string
	CSRFToken           string
}

type errorPageData struct {
	Title   string
	Message string
}

// authorizeParams bundles validated authorization request parameters.
type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// discoveryDoc is the OpenID Provider Configuration document.
type discoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
}

// registrationRequest is the RFC 7591 client registration request body.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// registrationResponse is the RFC 7591 client registration response body.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// --- discovery ---

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveDiscovery(w, r, de)
}

func (s *Server) serveDiscovery(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	base := issuerBase(r)
	algs, err := s.activeAlgorithmsFor(de.name)
	if err != nil {
		http.Error(w, "discovery: list algorithms", http.StatusInternalServerError)
		return
	}
	if len(algs) == 0 {
		// ensureSigningKeys guarantees one current key per loaded domain; an
		// empty result here means the DB row has been deleted out from under
		// us between startup and this request. Fail closed rather than
		// advertise an empty algorithm set.
		http.Error(w, "discovery: no active signing keys", http.StatusInternalServerError)
		return
	}
	doc := discoveryDoc{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/token",
		UserinfoEndpoint:                  base + "/userinfo",
		JWKSURI:                           base + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  algs,
		ScopesSupported:                   []string{"openid", "email", "profile"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post"},
		ClaimsSupported:                   []string{"sub", "email", "name", "iss", "aud", "exp", "iat"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}
	doc.RegistrationEndpoint = base + "/register"
	respondJSON(w, http.StatusOK, doc)
}

// --- jwks ---

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveJWKS(w, r, de)
}

func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request, de *domainEntry) {
	set, err := s.activePublicJWKsFor(de.name)
	if err != nil {
		http.Error(w, "jwks: load keys", http.StatusInternalServerError)
		return
	}
	if set.Len() == 0 {
		http.Error(w, "no active signing keys", http.StatusInternalServerError)
		return
	}
	b, err := json.Marshal(set)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// --- authorize ---

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveAuthorize(w, r, de)
}

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	q := r.URL.Query()
	params := authorizeParams{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
	}

	if q.Get("response_type") != "code" {
		renderError(w, http.StatusBadRequest, "Bad Request", "only response_type=code is supported")
		return
	}
	if err := s.validateParams(de, params); err != nil {
		renderError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Reuse existing SSO session if valid.
	if sessID := sessionCookie(r); sessID != "" {
		if sess, ok := s.store.LookupSession(sessID); ok && sess.Domain == de.name {
			s.issueCodeAndRedirect(w, r, de, sess.Username, params)
			return
		}
	}

	csrfToken := getOrSetCSRF(w, r)
	renderLoginForm(w, de, params, "", "", csrfToken)
}

// --- login ---

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveLogin(w, r, de)
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "Bad Request", "invalid form data")
		return
	}
	if !checkCSRF(r) {
		renderError(w, http.StatusForbidden, "Forbidden", "invalid or missing CSRF token")
		return
	}

	params := authorizeParams{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Nonce:               r.FormValue("nonce"),
	}
	if err := s.validateParams(de, params); err != nil {
		renderError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	rawUsername := r.FormValue("username")
	password := r.FormValue("password")
	csrfToken := getOrSetCSRF(w, r)

	localpart, err := normalizeLocalpart(rawUsername, de.name)
	if err != nil {
		renderLoginForm(w, de, params, rawUsername, "Invalid email or username.", csrfToken)
		return
	}

	_, authErr := de.agent.Authenticate(r.Context(), localpart, password)
	if authErr != nil {
		if errors.Is(authErr, autherrors.ErrUserNotFound) || errors.Is(authErr, autherrors.ErrAuthFailed) {
			renderLoginForm(w, de, params, rawUsername, "Invalid username or password.", csrfToken)
		} else {
			renderLoginForm(w, de, params, rawUsername, "An error occurred. Please try again.", csrfToken)
		}
		return
	}

	// Establish SSO session.
	sessID := generateToken(32)
	s.store.StoreSession(&ssoSession{
		ID:        sessID,
		Domain:    de.name,
		Username:  localpart,
		ExpiresAt: time.Now().Add(time.Duration(s.cfg.Server.SessionTTLSec) * time.Second),
	})
	setSessionCookie(w, r, sessID, s.cfg.Server.SessionTTLSec)

	s.issueCodeAndRedirect(w, r, de, localpart, params)
}

// --- token ---

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveToken(w, r, de)
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	if err := r.ParseForm(); err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		respondJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	c, err := s.store.ConsumeCode(code)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
		respondJSONError(w, http.StatusUnauthorized, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "server_error", "token exchange failed")
		return
	}

	if c.Domain != de.name {
		respondJSONError(w, http.StatusBadRequest, "invalid_grant", "domain mismatch")
		return
	}
	if c.ClientID != clientID {
		respondJSONError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if c.RedirectURI != redirectURI {
		respondJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(codeVerifier, c.PKCEChallenge, c.PKCEMethod) {
		respondJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	client, ok := s.clientFor(de, clientID)
	if !ok {
		respondJSONError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	// If client has a secret configured, verify it (client_secret_post).
	if client.Secret != "" {
		if subtle.ConstantTimeCompare([]byte(r.FormValue("client_secret")), []byte(client.Secret)) != 1 {
			respondJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	dk, err := s.currentKeyFor(de.name)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "server_error", "signing key unavailable")
		return
	}

	issuer := issuerBase(r)
	email := c.Username + "@" + de.name
	ttl := time.Duration(s.cfg.Server.JWTTTLSec) * time.Second

	accessToken, err := issueJWT(dk, issuer, clientID, c.Username, email, "", ttl)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	idToken, err := issueIDToken(dk, issuer, clientID, c.Username, email, c.Nonce, ttl)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}

	respondJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   s.cfg.Server.JWTTTLSec,
	})
}

// --- userinfo ---

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveUserinfo(w, r, de)
}

func (s *Server) serveUserinfo(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	rawToken := bearerToken(r)
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="auth-oidc"`)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	pubSet, err := s.activePublicJWKsFor(de.name)
	if err != nil {
		http.Error(w, "key error", http.StatusInternalServerError)
		return
	}
	if pubSet.Len() == 0 {
		http.Error(w, "no signing key", http.StatusInternalServerError)
		return
	}

	tok, err := jwt.Parse([]byte(rawToken),
		jwt.WithKeySet(pubSet),
		jwt.WithValidate(true),
		jwt.WithIssuer(issuerBase(r)),
	)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	claims := map[string]any{
		"sub": tok.Subject(),
	}
	if email, ok := tok.Get("email"); ok {
		claims["email"] = email
	}
	if name, ok := tok.Get("name"); ok {
		claims["name"] = name
	}
	respondJSON(w, http.StatusOK, claims)
}

// --- register (RFC 7591) ---

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveRegister(w, r, de)
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request, de *domainEntry) {
	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		respondJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	if len(req.RedirectURIs) > maxRedirectURIsPerReg {
		respondJSONError(w, http.StatusBadRequest, "invalid_redirect_uri",
			fmt.Sprintf("at most %d redirect_uris allowed per registration", maxRedirectURIsPerReg))
		return
	}
	if len(req.ClientName) > maxClientNameLen {
		respondJSONError(w, http.StatusBadRequest, "invalid_client_metadata",
			fmt.Sprintf("client_name exceeds %d bytes", maxClientNameLen))
		return
	}
	for _, uri := range req.RedirectURIs {
		if len(uri) > maxRedirectURILen {
			respondJSONError(w, http.StatusBadRequest, "invalid_redirect_uri",
				fmt.Sprintf("redirect_uri exceeds %d bytes", maxRedirectURILen))
			return
		}
		if err := validateRedirectURIScheme(uri); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	authMeth := req.TokenEndpointAuthMethod
	if authMeth == "" {
		authMeth = "none"
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Derive a stable client_id from the registration inputs so a restart of
	// auth-oidc, or a re-registration by a federated RP, yields the same id
	// for the same RP. The id is not a secret — exact-match redirect_uri plus
	// PKCE are the authorization-time controls (see
	// infodancer/docs/oidc-federation-design.md).
	clientID := deriveClientID(de.name, req.ClientName, req.RedirectURIs)

	if existing, ok := s.store.LookupClient(de.name, clientID); ok {
		if registrationMatches(existing, req.ClientName, req.RedirectURIs) {
			// RFC 7591 §3.2.1: idempotent re-registration preserves the
			// original client_id_issued_at.
			respondJSON(w, http.StatusOK, registrationResponse{
				ClientID:                existing.ClientID,
				ClientIDIssuedAt:        existing.RegisteredAt.Unix(),
				ClientName:              existing.ClientName,
				RedirectURIs:            existing.RedirectURIs,
				TokenEndpointAuthMethod: authMeth,
				GrantTypes:              grantTypes,
				ResponseTypes:           responseTypes,
			})
			return
		}
		// Statistically negligible at 120 bits but defend against it: derived
		// id collides with a different registration. Fall back to a random id
		// for this caller so neither registration is clobbered.
		clientID = generateToken(16)
	}

	now := time.Now()
	s.store.RegisterClient(&registeredClient{
		ClientID:     clientID,
		Domain:       de.name,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		RegisteredAt: now,
	})

	respondJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: authMeth,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
	})
}

// deriveClientID returns a stable opaque id for these registration inputs:
// SHA-256 over (domain, client_name, sorted redirect_uris) with NUL separators,
// truncated to 120 bits and base32-encoded.
//
// The id is not a secret — exact-match redirect_uri + PKCE are the
// authorization-time controls. Sorting redirect_uris makes the derivation
// order-independent: registering with [A, B] and [B, A] yields the same id.
func deriveClientID(domain, clientName string, redirectURIs []string) string {
	sorted := slices.Clone(redirectURIs)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(clientName))
	h.Write([]byte{0})
	for _, uri := range sorted {
		h.Write([]byte(uri))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return "dyn_" + strings.ToLower(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:15]))
}

// registrationMatches reports whether stored registration metadata is exactly
// equal to the metadata in this request. redirect_uris equality is order-
// independent, mirroring deriveClientID.
func registrationMatches(stored *registeredClient, clientName string, redirectURIs []string) bool {
	if stored.ClientName != clientName {
		return false
	}
	if len(stored.RedirectURIs) != len(redirectURIs) {
		return false
	}
	a := slices.Clone(stored.RedirectURIs)
	b := slices.Clone(redirectURIs)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// --- logout ---

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}
	s.serveLogout(w, r, de)
}

func (s *Server) serveLogout(w http.ResponseWriter, r *http.Request, _ *domainEntry) {
	if sessID := sessionCookie(r); sessID != "" {
		s.store.DeleteSession(sessID)
	}
	clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, de *domainEntry, username string, params authorizeParams) {
	code := generateToken(24)
	s.store.StoreCode(&authCode{
		Code:          code,
		Domain:        de.name,
		ClientID:      params.ClientID,
		Username:      username,
		RedirectURI:   params.RedirectURI,
		PKCEChallenge: params.CodeChallenge,
		PKCEMethod:    params.CodeChallengeMethod,
		Nonce:         params.Nonce,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	})

	redirectTo, _ := url.Parse(params.RedirectURI)
	q := redirectTo.Query()
	q.Set("code", code)
	if params.State != "" {
		q.Set("state", params.State)
	}
	redirectTo.RawQuery = q.Encode()
	http.Redirect(w, r, redirectTo.String(), http.StatusFound)
}

func (s *Server) validateParams(de *domainEntry, params authorizeParams) error {
	if params.ClientID == "" {
		return errors.New("client_id is required")
	}
	if params.RedirectURI == "" {
		return errors.New("redirect_uri is required")
	}
	if params.CodeChallenge == "" {
		return errors.New("code_challenge is required (PKCE)")
	}
	if params.CodeChallengeMethod != "S256" {
		return errors.New("code_challenge_method must be S256")
	}
	client, ok := s.clientFor(de, params.ClientID)
	if !ok {
		return errors.New("unknown client_id")
	}
	if !validRedirectURI(client, params.RedirectURI) {
		return errors.New("redirect_uri not registered for this client")
	}
	return nil
}

func issueJWT(k *loadedKey, issuer, audience, sub, email, name string, ttl time.Duration) (string, error) {
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		Claim("email", email)
	if name != "" {
		b = b.Claim("name", name)
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build jwt: %w", err)
	}
	alg, err := jwaAlgorithm(k.algorithm)
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, k.privJWK))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
}

func issueIDToken(k *loadedKey, issuer, audience, sub, email, nonce string, ttl time.Duration) (string, error) {
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		Claim("email", email).
		Claim("auth_time", now.Unix())
	if nonce != "" {
		b = b.Claim("nonce", nonce)
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build id_token: %w", err)
	}
	alg, err := jwaAlgorithm(k.algorithm)
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, k.privJWK))
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}
	return string(signed), nil
}

func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func normalizeLocalpart(input, domainName string) (string, error) {
	local, d, hasAt := strings.Cut(input, "@")
	if hasAt && d != domainName {
		return "", fmt.Errorf("email domain %q does not match tenant %q", d, domainName)
	}
	return local, nil
}

func sessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, id string, ttlSec int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(ttlSec),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func getOrSetCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token := generateToken(16)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // must be readable by the form
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func checkCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	formToken := r.FormValue("csrf_token")
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) == 1
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return after
	}
	return ""
}

func renderLoginForm(w http.ResponseWriter, de *domainEntry, params authorizeParams, username, errMsg, csrfToken string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	_ = loginTmpl.Execute(w, loginFormData{
		Domain:              de.name,
		LoginAction:         "/login",
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Nonce:               params.Nonce,
		Username:            username,
		Error:               errMsg,
		CSRFToken:           csrfToken,
	})
}

func renderError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorTmpl.Execute(w, errorPageData{Title: title, Message: message})
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func respondJSONError(w http.ResponseWriter, status int, errCode, description string) {
	respondJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

// Cleanup runs one synchronous sweep of expired codes and sessions. The
// background goroutine started by New already does this every sweepInterval;
// this method exists for tests and for operators who want to force a sweep.
func (s *Server) Cleanup(_ context.Context) {
	if s.store != nil {
		_ = s.store.SweepExpired(time.Now())
	}
}
