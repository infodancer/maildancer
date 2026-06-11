package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infodancer/maildancer/internal/admin"
)

// fakeDNSResolver serves canned answers; anything not configured returns a
// not-found error. The check logic itself is tested in internal/admin --
// these tests cover the HTTP layer.
type fakeDNSResolver struct {
	hosts map[string][]string
	mxs   map[string][]*net.MX
	txts  map[string][]string
	ptrs  map[string][]string
}

var errFakeNXDomain = errors.New("no such host")

func (f *fakeDNSResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if v, ok := f.hosts[host]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeDNSResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := f.mxs[name]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txts[name]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeDNSResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptrs[addr]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func newTestDNSHandler(t *testing.T, resolver admin.Resolver) (*DNSHandler, string) {
	t.Helper()
	dir := t.TempDir()
	h := NewDNSHandler(dir, nil, nil, nil)
	h.resolver = resolver
	return h, dir
}

func checkDNSRequest(h *DNSHandler, domain, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/domains/"+domain+"/dns/check?"+query, nil)
	req.SetPathValue("name", domain)
	rr := httptest.NewRecorder()
	h.HandleCheckDNSRecord(rr, req)
	return rr
}

func TestHandleCheckDNSRecord_Validation(t *testing.T) {
	h, dir := newTestDNSHandler(t, &fakeDNSResolver{})
	createTestDomain(t, dir, "example.com")

	cases := []struct {
		name   string
		domain string
		query  string
		want   int
	}{
		{"invalid domain", "../etc", "type=mx&ip=192.0.2.1", http.StatusBadRequest},
		{"unknown domain", "missing.example", "type=mx&ip=192.0.2.1", http.StatusNotFound},
		{"missing ip", "example.com", "type=mx", http.StatusBadRequest},
		{"bad ip", "example.com", "type=mx&ip=not-an-ip", http.StatusBadRequest},
		{"bad type", "example.com", "type=frobnicate&ip=192.0.2.1", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rr := checkDNSRequest(h, tc.domain, tc.query); rr.Code != tc.want {
				t.Errorf("got %d, want %d: %s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestHandleCheckDNSRecord_MX(t *testing.T) {
	resolver := &fakeDNSResolver{
		mxs: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.net.", Pref: 10}},
		},
		hosts: map[string][]string{
			"mail.example.net": {"192.0.2.25"},
		},
	}
	h, dir := newTestDNSHandler(t, resolver)
	createTestDomain(t, dir, "example.com")

	rr := checkDNSRequest(h, "example.com", "type=mx&ip=192.0.2.25&hostname=mail.example.net")
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	var result DNSCheckResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Type != "mx" || result.Status != admin.DNSStatusOK {
		t.Errorf("result = %+v, want mx/ok", result)
	}
}

func TestHandleCheckDNSRecord_DKIMUnconfigured(t *testing.T) {
	h, dir := newTestDNSHandler(t, &fakeDNSResolver{})
	createTestDomain(t, dir, "example.com")

	rr := checkDNSRequest(h, "example.com", "type=dkim&ip=192.0.2.25")
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	var result DNSCheckResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// No local DKIM key configured: a warning, not a guess about selectors.
	if result.Status != admin.DNSStatusWarning {
		t.Errorf("status = %q, want warning: %+v", result.Status, result)
	}
}
