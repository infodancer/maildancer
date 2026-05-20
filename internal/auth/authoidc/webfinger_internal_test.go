package authoidc

import "testing"

func TestWebfingerIssuerURL_DefaultTemplate(t *testing.T) {
	s := &Server{cfg: &Config{}}
	got := s.webfingerIssuerURL("infodancer.net")
	if got != "https://auth.infodancer.net" {
		t.Errorf("default template = %q, want https://auth.infodancer.net", got)
	}
}

func TestWebfingerIssuerURL_TemplateOverride(t *testing.T) {
	s := &Server{cfg: &Config{Server: ServerConfig{
		WebfingerIssuerTemplate: "https://oidc.{domain}",
	}}}
	got := s.webfingerIssuerURL("infodancer.net")
	if got != "https://oidc.infodancer.net" {
		t.Errorf("override template = %q, want https://oidc.infodancer.net", got)
	}
}

func TestWebfingerIssuerURL_TemplateAtApex(t *testing.T) {
	// Deployments that run auth-oidc at the apex itself can elide auth.
	s := &Server{cfg: &Config{Server: ServerConfig{
		WebfingerIssuerTemplate: "https://{domain}",
	}}}
	got := s.webfingerIssuerURL("infodancer.net")
	if got != "https://infodancer.net" {
		t.Errorf("apex template = %q, want https://infodancer.net", got)
	}
}
