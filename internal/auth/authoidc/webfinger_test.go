package authoidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebfinger_KnownDomain_ReturnsIssuerLink probes the apex Host and
// verifies the JRD points at the canonical auth.<domain> issuer.
func TestWebfinger_KnownDomain_ReturnsIssuerLink(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/webfinger?resource=acct:alice@test.example"+
			"&rel=http://openid.net/specs/connect/1.0/issuer", nil)
	req.Host = "test.example" // apex — domainForHost matches directly
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var doc struct {
		Subject string `json:"subject"`
		Links   []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode JRD: %v", err)
	}
	if doc.Subject != "acct:alice@test.example" {
		t.Errorf("subject=%q, want echoed input", doc.Subject)
	}
	if len(doc.Links) != 1 {
		t.Fatalf("links=%d, want 1", len(doc.Links))
	}
	if doc.Links[0].Rel != "http://openid.net/specs/connect/1.0/issuer" {
		t.Errorf("link rel=%q", doc.Links[0].Rel)
	}
	if doc.Links[0].Href != "https://auth.test.example" {
		t.Errorf("link href=%q, want https://auth.test.example", doc.Links[0].Href)
	}
}

// TestWebfinger_ResolvesViaSubdomainStripping verifies that a request to
// auth.<domain>/.well-known/webfinger also resolves correctly — domainForHost
// strips the "auth." label and finds the registered domain.
func TestWebfinger_ResolvesViaSubdomainStripping(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/webfinger?resource=acct:alice@test.example", nil)
	req.Host = "auth.test.example"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

// TestWebfinger_UnknownDomain_404 confirms that a Host not matching any
// registered domain returns the same error domainForHost emits elsewhere.
func TestWebfinger_UnknownDomain_404(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/webfinger?resource=acct:alice@unknown.example", nil)
	req.Host = "unknown.example"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("status = %d, want non-200 for unknown domain", rr.Code)
	}
}

// TestWebfinger_ContentType_IsJRD confirms RFC 7033 §10.2 compliance.
func TestWebfinger_ContentType_IsJRD(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/webfinger", nil)
	req.Host = "test.example"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Type"); got != "application/jrd+json" {
		t.Errorf("Content-Type=%q, want application/jrd+json", got)
	}
}

// TestWebfinger_IgnoresResourceLocalpart verifies that callers can pass
// either a placeholder (broker-side, acct:_@<domain>) or a real address
// (eventual user-flow case) and get the same canonical issuer link.
func TestWebfinger_IgnoresResourceLocalpart(t *testing.T) {
	handler := newTestServer(t)

	cases := []string{
		"acct:_@test.example",
		"acct:alice@test.example",
		"acct:nobody@test.example",
	}
	for _, resource := range cases {
		t.Run(resource, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/.well-known/webfinger?resource="+resource, nil)
			req.Host = "test.example"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d for resource=%q", rr.Code, resource)
			}
			if !strings.Contains(rr.Body.String(), `"href":"https://auth.test.example"`) {
				t.Errorf("issuer link missing or wrong for resource=%q; body=%s", resource, rr.Body.String())
			}
		})
	}
}

// TestWebfinger_NoResourceParam_PlaceholderSubject confirms graceful default
// when the broker omits ?resource= (allowed because OIDC issuer discovery
// is domain-keyed, not account-keyed).
func TestWebfinger_NoResourceParam_PlaceholderSubject(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/webfinger", nil)
	req.Host = "test.example"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"subject":"acct:_@test.example"`) {
		t.Errorf("missing placeholder subject; body=%s", rr.Body.String())
	}
}
