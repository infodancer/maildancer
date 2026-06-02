package authoidc

import (
	"encoding/json"
	"net/http"
	"strings"
)

// oidcIssuerRel is the link relation that identifies an OIDC issuer in an
// RFC 7033 webfinger response (per OIDC §2).
const oidcIssuerRel = "http://openid.net/specs/connect/1.0/issuer"

// defaultWebfingerIssuerTemplate is used when ServerConfig.WebfingerIssuerTemplate
// is empty — the standard homelab topology where auth-oidc lives at
// auth.<domain> and the apex answers webfinger.
const defaultWebfingerIssuerTemplate = "https://auth.{domain}"

// webfingerLink is one entry in a JRD links array.
type webfingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// webfingerJRD is the subset of RFC 7033 §4.4 we emit. Only the OIDC
// issuer link is populated; other relations would be added if a consumer
// needs them.
type webfingerJRD struct {
	Subject string          `json:"subject"`
	Links   []webfingerLink `json:"links"`
}

// webfinger answers RFC 7033 discovery requests so a federation broker
// probing https://<domain>/.well-known/webfinger gets back a JRD pointing
// at this server as the OIDC issuer for <domain>.
//
// The set of domains we serve is the set of registered OIDC client domains
// (the same source domainForHost uses). We do not maintain a separate
// "webfinger domains" list — the registration is the authoritative source.
//
// The issuer URL we advertise is built from WebfingerIssuerTemplate with
// "{domain}" substituted. Default template "https://auth.{domain}" matches
// the homelab topology; deployments where auth-oidc lives elsewhere set
// the template explicitly.
//
// The `resource` query parameter is echoed in the response per RFC 7033
// §4.4; localpart is not interpreted, since the broker calls webfinger
// with a placeholder identifier (e.g., acct:_@<domain>) at probe time.
func (s *Server) webfinger(w http.ResponseWriter, r *http.Request) {
	de, ok := s.domainForHost(w, r)
	if !ok {
		return
	}

	resource := r.URL.Query().Get("resource")
	if resource == "" {
		resource = "acct:_@" + de.name
	}

	issuerURL := s.webfingerIssuerURL(de.name)

	doc := webfingerJRD{
		Subject: resource,
		Links: []webfingerLink{
			{Rel: oidcIssuerRel, Href: issuerURL},
		},
	}

	w.Header().Set("Content-Type", "application/jrd+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// webfingerIssuerURL applies ServerConfig.WebfingerIssuerTemplate to domain.
// Empty template falls back to the standard "https://auth.{domain}" default.
func (s *Server) webfingerIssuerURL(domain string) string {
	tpl := s.cfg.Server.WebfingerIssuerTemplate
	if tpl == "" {
		tpl = defaultWebfingerIssuerTemplate
	}
	return strings.ReplaceAll(tpl, "{domain}", domain)
}
