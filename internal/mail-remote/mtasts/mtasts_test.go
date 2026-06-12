package mtasts

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- policy text parsing ---

func TestParsePolicy(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 86400\n"
	p, err := ParsePolicy(body)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Mode != ModeEnforce {
		t.Errorf("Mode = %q", p.Mode)
	}
	if len(p.MXs) != 2 || p.MXs[0] != "mail.example.com" || p.MXs[1] != "*.backup.example.com" {
		t.Errorf("MXs = %v", p.MXs)
	}
	if p.MaxAge != 86400 {
		t.Errorf("MaxAge = %d", p.MaxAge)
	}
}

func TestParsePolicy_CRLFAndSpacing(t *testing.T) {
	body := "version:STSv1\r\nmode:  testing\r\nmx:mail.example.com\r\nmax_age:3600\r\n"
	p, err := ParsePolicy(body)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Mode != ModeTesting || p.MaxAge != 3600 || len(p.MXs) != 1 {
		t.Errorf("policy = %+v", p)
	}
}

func TestParsePolicy_Invalid(t *testing.T) {
	cases := map[string]string{
		"wrong version":       "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 60\n",
		"missing version":     "mode: enforce\nmx: a.example\nmax_age: 60\n",
		"missing mode":        "version: STSv1\nmx: a.example\nmax_age: 60\n",
		"bad mode":            "version: STSv1\nmode: frobnicate\nmx: a.example\nmax_age: 60\n",
		"enforce without mx":  "version: STSv1\nmode: enforce\nmax_age: 60\n",
		"missing max_age":     "version: STSv1\nmode: enforce\nmx: a.example\n",
		"non-numeric max_age": "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: soon\n",
		"negative max_age":    "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -5\n",
	}
	for name, body := range cases {
		if _, err := ParsePolicy(body); err == nil {
			t.Errorf("%s: ParsePolicy succeeded, want error", name)
		}
	}
}

func TestParsePolicy_MaxAgeCapped(t *testing.T) {
	body := "version: STSv1\nmode: none\nmax_age: 99999999999\n"
	p, err := ParsePolicy(body)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.MaxAge != maxMaxAge {
		t.Errorf("MaxAge = %d, want capped to %d", p.MaxAge, maxMaxAge)
	}
}

// --- MX pattern matching ---

func TestMXMatches(t *testing.T) {
	p := &Policy{MXs: []string{"mail.example.com", "*.relay.example.com"}}
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},
		{"MAIL.EXAMPLE.COM", true}, // case-insensitive
		{"mail2.example.com", false},
		{"a.relay.example.com", true},
		{"B.RELAY.example.com", true},
		{"a.b.relay.example.com", false}, // wildcard is one label only
		{"relay.example.com", false},     // wildcard requires the extra label
		{"example.com", false},
	}
	for _, tc := range cases {
		if got := p.MXMatches(tc.host); got != tc.want {
			t.Errorf("MXMatches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// --- TXT record parsing ---

func TestParseTXTRecord(t *testing.T) {
	id, ok := parseTXT([]string{"v=STSv1; id=20260611T000000;"})
	if !ok || id != "20260611T000000" {
		t.Errorf("got id=%q ok=%v", id, ok)
	}

	// Unrelated TXT records are ignored.
	id, ok = parseTXT([]string{"v=spf1 -all", "v=STSv1; id=abc"})
	if !ok || id != "abc" {
		t.Errorf("got id=%q ok=%v", id, ok)
	}

	// No STS record.
	if _, ok := parseTXT([]string{"v=spf1 -all"}); ok {
		t.Error("expected ok=false without STS record")
	}

	// Multiple STSv1 records: invalid per RFC 8461, treated as no policy.
	if _, ok := parseTXT([]string{"v=STSv1; id=a", "v=STSv1; id=b"}); ok {
		t.Error("expected ok=false for duplicate STS records")
	}
}

// --- checker with cache ---

type fakeTXT struct {
	txts map[string][]string
}

func (f *fakeTXT) LookupTXT(name string) ([]string, error) {
	if v, ok := f.txts[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

const enforcePolicy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"

func newTestChecker(t *testing.T, txtID string, fetchBody string, fetchErr error) (*Checker, *int) {
	t.Helper()
	fetches := 0
	resolver := &fakeTXT{txts: map[string][]string{}}
	if txtID != "" {
		resolver.txts["_mta-sts.example.com"] = []string{"v=STSv1; id=" + txtID}
	}
	c := &Checker{
		Resolver: resolver,
		Fetch: func(domain string) (string, error) {
			fetches++
			if fetchErr != nil {
				return "", fetchErr
			}
			return fetchBody, nil
		},
		CacheDir: t.TempDir(),
		Now:      time.Now,
	}
	return c, &fetches
}

func TestChecker_FetchesAndCaches(t *testing.T) {
	c, fetches := newTestChecker(t, "id1", enforcePolicy, nil)

	p, err := c.PolicyFor("example.com")
	if err != nil {
		t.Fatalf("PolicyFor: %v", err)
	}
	if p == nil || p.Mode != ModeEnforce {
		t.Fatalf("policy = %+v", p)
	}

	// Second call with the same id is served from cache.
	p2, err := c.PolicyFor("example.com")
	if err != nil || p2 == nil {
		t.Fatalf("second PolicyFor: %+v, %v", p2, err)
	}
	if *fetches != 1 {
		t.Errorf("fetches = %d, want 1 (cache hit)", *fetches)
	}
}

func TestChecker_IDChangeRefetches(t *testing.T) {
	c, fetches := newTestChecker(t, "id1", enforcePolicy, nil)
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}

	// The domain publishes a new id: refetch.
	c.Resolver.(*fakeTXT).txts["_mta-sts.example.com"] = []string{"v=STSv1; id=id2"}
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}
	if *fetches != 2 {
		t.Errorf("fetches = %d, want 2 (id change)", *fetches)
	}
}

func TestChecker_NoTXTNoCache(t *testing.T) {
	c, _ := newTestChecker(t, "", "", nil)
	p, err := c.PolicyFor("example.com")
	if err != nil {
		t.Fatalf("PolicyFor: %v", err)
	}
	if p != nil {
		t.Errorf("expected no policy, got %+v", p)
	}
}

func TestChecker_CacheSurvivesTXTOutage(t *testing.T) {
	// Security property: an attacker who blocks the TXT lookup must not
	// downgrade a domain with a previously-seen enforce policy.
	c, _ := newTestChecker(t, "id1", enforcePolicy, nil)
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}

	delete(c.Resolver.(*fakeTXT).txts, "_mta-sts.example.com")
	p, err := c.PolicyFor("example.com")
	if err != nil {
		t.Fatalf("PolicyFor during outage: %v", err)
	}
	if p == nil || p.Mode != ModeEnforce {
		t.Errorf("cached enforce policy not served during TXT outage: %+v", p)
	}
}

func TestChecker_CacheSurvivesFetchFailure(t *testing.T) {
	c, _ := newTestChecker(t, "id1", enforcePolicy, nil)
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}

	// New id, but the policy host is unreachable: serve the cached policy.
	c.Resolver.(*fakeTXT).txts["_mta-sts.example.com"] = []string{"v=STSv1; id=id2"}
	c.Fetch = func(string) (string, error) { return "", errors.New("connection refused") }

	p, err := c.PolicyFor("example.com")
	if err != nil {
		t.Fatalf("PolicyFor with fetch failure: %v", err)
	}
	if p == nil || p.Mode != ModeEnforce {
		t.Errorf("cached policy not served on fetch failure: %+v", p)
	}
}

func TestChecker_CacheExpires(t *testing.T) {
	c, fetches := newTestChecker(t, "id1", enforcePolicy, nil)
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}

	// Advance past max_age: same id still refetches.
	c.Now = func() time.Time { return time.Now().Add(87000 * time.Second) }
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}
	if *fetches != 2 {
		t.Errorf("fetches = %d, want 2 (cache expired)", *fetches)
	}

	// Expired cache + TXT outage + nothing fetchable = no policy. The
	// refetch above renewed the cache, so expire it again first.
	c.Now = func() time.Time { return time.Now().Add(2 * 87000 * time.Second) }
	delete(c.Resolver.(*fakeTXT).txts, "_mta-sts.example.com")
	p, err := c.PolicyFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("expired cache served during outage: %+v", p)
	}
}

func TestChecker_NoCacheDirStillWorks(t *testing.T) {
	c, fetches := newTestChecker(t, "id1", enforcePolicy, nil)
	c.CacheDir = ""

	p, err := c.PolicyFor("example.com")
	if err != nil || p == nil {
		t.Fatalf("PolicyFor: %+v, %v", p, err)
	}
	if _, err := c.PolicyFor("example.com"); err != nil {
		t.Fatal(err)
	}
	if *fetches != 2 {
		t.Errorf("fetches = %d, want 2 (no cache dir)", *fetches)
	}
}

func TestChecker_BadPolicyBody(t *testing.T) {
	c, _ := newTestChecker(t, "id1", "this is not a policy", nil)
	p, err := c.PolicyFor("example.com")
	if err == nil && p != nil {
		t.Errorf("expected no policy for unparseable body, got %+v", p)
	}
}

// --- HTTPS fetcher ---

func TestHTTPSFetcher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, enforcePolicy)
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	fetch := httpsFetcherForTest(srv, pool)
	body, err := fetch("example.com")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !strings.Contains(body, "mode: enforce") {
		t.Errorf("body = %q", body)
	}
}

func TestHTTPSFetcher_RefusesRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/policy", http.StatusFound)
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	fetch := httpsFetcherForTest(srv, pool)
	if _, err := fetch("example.com"); err == nil {
		t.Error("expected error on redirect, got success")
	}
}

// httpsFetcherForTest builds a fetcher pointed at a local httptest TLS
// server, trusting its certificate.
func httpsFetcherForTest(srv *httptest.Server, pool *x509.CertPool) func(string) (string, error) {
	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: refuseRedirect,
		Timeout:       5 * time.Second,
	}
	return newFetcher(client, func(string) string {
		return srv.URL + "/.well-known/mta-sts.txt"
	})
}
