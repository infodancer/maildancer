package authoidc

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssuerBase_HonorsForwardedProto(t *testing.T) {
	// Behind a TLS-terminating proxy (Traefik), the backend connection is
	// plain HTTP (r.TLS == nil) but the proxy sets X-Forwarded-Proto: https.
	// The advertised issuer must be https, or conformant brokers reject the
	// discovery document and the ID-token iss claim.
	req := httptest.NewRequest("GET", "http://auth.example.com/.well-known/openid-configuration", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	if got := issuerBase(req); got != "https://auth.example.com" {
		t.Errorf("issuerBase = %q, want https://auth.example.com", got)
	}
}

func TestIssuerBase_ForwardedProtoMultiValue(t *testing.T) {
	// X-Forwarded-Proto may be a comma-separated list when chained through
	// multiple proxies; the client-facing (first) value is authoritative.
	req := httptest.NewRequest("GET", "http://auth.example.com/x", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")

	if got := issuerBase(req); got != "https://auth.example.com" {
		t.Errorf("issuerBase = %q, want https://auth.example.com", got)
	}
}

func TestIssuerBase_DirectTLS(t *testing.T) {
	// No proxy: TLS terminated in-process. httptest populates req.TLS for an
	// https target.
	req := httptest.NewRequest("GET", "https://auth.example.com/x", nil)

	if got := issuerBase(req); got != "https://auth.example.com" {
		t.Errorf("issuerBase = %q, want https://auth.example.com", got)
	}
}

func TestIssuerBase_PlainHTTPLocalDev(t *testing.T) {
	// Local development with neither TLS nor a forwarding proxy stays http,
	// per the project's "document when HTTP is intentionally used locally".
	req := httptest.NewRequest("GET", "http://localhost:8080/x", nil)

	if got := issuerBase(req); got != "http://localhost:8080" {
		t.Errorf("issuerBase = %q, want http://localhost:8080", got)
	}
}

func TestDeriveClientID_Stable(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://app.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://app.example/cb"})
	if a != b {
		t.Errorf("same inputs should yield same id: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "dyn_") {
		t.Errorf("id should be prefixed with dyn_: %q", a)
	}
}

func TestDeriveClientID_DomainVaries(t *testing.T) {
	a := deriveClientID("a.example", "myapp", []string{"https://app.example/cb"})
	b := deriveClientID("b.example", "myapp", []string{"https://app.example/cb"})
	if a == b {
		t.Errorf("different domains should yield different ids: %q", a)
	}
}

func TestDeriveClientID_ClientNameVaries(t *testing.T) {
	a := deriveClientID("test.example", "appA", []string{"https://app.example/cb"})
	b := deriveClientID("test.example", "appB", []string{"https://app.example/cb"})
	if a == b {
		t.Errorf("different client_names should yield different ids: %q", a)
	}
}

func TestDeriveClientID_RedirectURIsVary(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://a.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://b.example/cb"})
	if a == b {
		t.Errorf("different redirect_uris should yield different ids: %q", a)
	}
}

func TestDeriveClientID_OrderIndependent(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://a.example/cb", "https://b.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://b.example/cb", "https://a.example/cb"})
	if a != b {
		t.Errorf("redirect_uri order should not affect id: %q vs %q", a, b)
	}
}

// TestDeriveClientID_DoesNotMutateInput verifies the helper does not reorder
// the caller's slice (sorting happens on a clone).
func TestDeriveClientID_DoesNotMutateInput(t *testing.T) {
	uris := []string{"https://z.example/cb", "https://a.example/cb"}
	original := append([]string(nil), uris...)
	_ = deriveClientID("test.example", "myapp", uris)
	for i, v := range original {
		if uris[i] != v {
			t.Errorf("deriveClientID mutated caller's slice at %d: %q vs %q", i, uris[i], v)
		}
	}
}

func TestRegistrationMatches(t *testing.T) {
	stored := &registeredClient{
		ClientName:   "myapp",
		RedirectURIs: []string{"https://a.example/cb", "https://b.example/cb"},
	}

	// Exact match.
	if !registrationMatches(stored, "myapp", []string{"https://a.example/cb", "https://b.example/cb"}) {
		t.Error("exact match should be true")
	}

	// Order-independent match.
	if !registrationMatches(stored, "myapp", []string{"https://b.example/cb", "https://a.example/cb"}) {
		t.Error("reordered redirect_uris should still match")
	}

	// Different client_name.
	if registrationMatches(stored, "otherapp", []string{"https://a.example/cb", "https://b.example/cb"}) {
		t.Error("different client_name should not match")
	}

	// Different redirect_uri count.
	if registrationMatches(stored, "myapp", []string{"https://a.example/cb"}) {
		t.Error("different redirect_uri count should not match")
	}

	// Different redirect_uri value.
	if registrationMatches(stored, "myapp", []string{"https://a.example/cb", "https://c.example/cb"}) {
		t.Error("different redirect_uri value should not match")
	}
}
