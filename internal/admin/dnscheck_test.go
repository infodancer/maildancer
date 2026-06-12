package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// fakeResolver serves DNS answers from maps. Missing keys return a
// not-found error, like a real NXDOMAIN.
type fakeResolver struct {
	hosts map[string][]string // name -> A/AAAA
	mxs   map[string][]*net.MX
	txts  map[string][]string
	ptrs  map[string][]string // ip -> names
}

var errNXDomain = errors.New("no such host")

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if v, ok := f.hosts[host]; ok {
		return v, nil
	}
	return nil, errNXDomain
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := f.mxs[name]; ok {
		return v, nil
	}
	return nil, errNXDomain
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txts[name]; ok {
		return v, nil
	}
	return nil, errNXDomain
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptrs[addr]; ok {
		return v, nil
	}
	return nil, errNXDomain
}

// goodResolver returns a resolver where example.com is fully, correctly
// configured for a server at mail.example.net / 192.0.2.25, with DKIM
// published under the given selector and TXT value.
func goodResolver(selector, dkimTXT string) *fakeResolver {
	return &fakeResolver{
		hosts: map[string][]string{
			"example.com":      {"192.0.2.25"},
			"mail.example.net": {"192.0.2.25"},
		},
		mxs: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.net.", Pref: 10}},
		},
		txts: map[string][]string{
			"example.com":                        {"v=spf1 ip4:192.0.2.25 -all"},
			"_dmarc.example.com":                 {"v=DMARC1; p=quarantine"},
			selector + "._domainkey.example.com": {dkimTXT},
		},
		ptrs: map[string][]string{
			"192.0.2.25": {"mail.example.net."},
		},
	}
}

func dnsTestPaths(t *testing.T) (Paths, *DKIMRecord) {
	t.Helper()
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	rec, err := p.CreateDKIMKey("example.com", "sel1", false)
	if err != nil {
		t.Fatal(err)
	}
	return p, rec
}

func checksByType(checks []DNSCheck) map[string]DNSCheck {
	m := make(map[string]DNSCheck, len(checks))
	for _, c := range checks {
		m[c.Type] = c
	}
	return m
}

func TestCheckDomainDNS_AllGood(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatalf("CheckDomainDNS: %v", err)
	}
	if len(checks) != 6 {
		t.Fatalf("expected 6 checks, got %d", len(checks))
	}
	wantOrder := []string{"a", "mx", "ptr", "spf", "dkim", "dmarc"}
	for i, typ := range wantOrder {
		if checks[i].Type != typ {
			t.Errorf("checks[%d].Type = %q, want %q", i, checks[i].Type, typ)
		}
	}
	for _, c := range checks {
		if c.Status != DNSStatusOK {
			t.Errorf("%s: status %q (%s), want ok", c.Type, c.Status, c.Message)
		}
	}
}

func TestCheckDomainDNS_EmptyZone(t *testing.T) {
	p, _ := dnsTestPaths(t)
	r := &fakeResolver{} // nothing resolves

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatalf("CheckDomainDNS: %v", err)
	}
	m := checksByType(checks)

	for _, typ := range []string{"a", "mx", "dmarc", "spf", "ptr"} {
		if m[typ].Status != DNSStatusError {
			t.Errorf("%s: status %q, want error", typ, m[typ].Status)
		}
	}
	// DKIM is locally configured, so a missing record is an error, and the
	// message carries the value to publish.
	if m["dkim"].Status != DNSStatusError {
		t.Errorf("dkim: status %q, want error", m["dkim"].Status)
	}
}

func TestCheckDomainDNS_DKIMKeyMismatch(t *testing.T) {
	p, _ := dnsTestPaths(t)
	wrong := "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	r := goodResolver("sel1", wrong)

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	dkim := checksByType(checks)["dkim"]
	if dkim.Status != DNSStatusError {
		t.Errorf("dkim mismatch: status %q (%s), want error", dkim.Status, dkim.Message)
	}
}

func TestCheckDomainDNS_DKIMNotConfiguredLocally(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	r := goodResolver("sel1", "v=DKIM1; k=ed25519; p=xyz")

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	dkim := checksByType(checks)["dkim"]
	if dkim.Status != DNSStatusWarning {
		t.Errorf("dkim unconfigured: status %q, want warning", dkim.Status)
	}
	if !strings.Contains(dkim.Message, "dkim create") {
		t.Errorf("dkim message should point at key creation, got %q", dkim.Message)
	}
}

func TestCheckDomainDNS_SmarthostSPF(t *testing.T) {
	p, rec := dnsTestPaths(t)
	if err := p.SetDomainConfig("example.com", "outbound.strategy", "smarthost"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetDomainConfig("example.com", "outbound.smarthost", "smtp.relay.example:587"); err != nil {
		t.Fatal(err)
	}
	// SPF record covers the relay, not our IP.
	r := goodResolver("sel1", rec.DNSValue)
	r.txts["example.com"] = []string{"v=spf1 include:relay.example -all"}

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	spf := checksByType(checks)["spf"]
	// We cannot evaluate include: mechanisms; smarthost domains get a
	// warning asking the operator to confirm coverage, never a hard error.
	if spf.Status != DNSStatusWarning {
		t.Errorf("smarthost spf: status %q, want warning", spf.Status)
	}
	if !strings.Contains(spf.Message, "smtp.relay.example") {
		t.Errorf("smarthost spf message should name the smarthost, got %q", spf.Message)
	}

	// A missing SPF record is still an error even for smarthost domains.
	delete(r.txts, "example.com")
	checks, err = p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	if spf := checksByType(checks)["spf"]; spf.Status != DNSStatusError {
		t.Errorf("missing smarthost spf: status %q, want error", spf.Status)
	}
}

func TestCheckDomainDNS_NoIP(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	m := checksByType(checks)

	// IP-dependent checks degrade to warnings explaining the gap rather
	// than reporting pass/fail off an unknown IP.
	for _, typ := range []string{"a", "ptr", "spf"} {
		if m[typ].Status != DNSStatusWarning {
			t.Errorf("%s without IP: status %q, want warning", typ, m[typ].Status)
		}
	}
	// MX can still be verified by hostname match.
	if m["mx"].Status != DNSStatusOK {
		t.Errorf("mx by hostname: status %q (%s), want ok", m["mx"].Status, m["mx"].Message)
	}
	// DKIM and DMARC don't need the IP at all.
	if m["dkim"].Status != DNSStatusOK || m["dmarc"].Status != DNSStatusOK {
		t.Errorf("dkim=%q dmarc=%q, want ok", m["dkim"].Status, m["dmarc"].Status)
	}
}

func TestCheckDomainDNS_MXByHostname(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)
	// MX host matches the expected hostname but resolves elsewhere.
	r.hosts["mail.example.net"] = []string{"198.51.100.1"}

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	mx := checksByType(checks)["mx"]
	if mx.Status != DNSStatusOK {
		t.Errorf("mx hostname match: status %q (%s), want ok", mx.Status, mx.Message)
	}
}

func TestCheckDomainDNS_WrongMX(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)
	r.mxs["example.com"] = []*net.MX{{Host: "mx.elsewhere.example.", Pref: 10}}

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	mx := checksByType(checks)["mx"]
	if mx.Status != DNSStatusWarning {
		t.Errorf("wrong mx: status %q, want warning", mx.Status)
	}
}

func TestCheckDomainDNS_WrongPTR(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)
	r.ptrs["192.0.2.25"] = []string{"generic-25.isp.example."}

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	ptr := checksByType(checks)["ptr"]
	if ptr.Status != DNSStatusWarning {
		t.Errorf("wrong ptr: status %q, want warning", ptr.Status)
	}
}

func TestCheckDomainDNS_Validation(t *testing.T) {
	p := newTestPaths(t)
	r := &fakeResolver{}
	target := DNSTarget{Hostname: "mail.example.net"}

	if _, err := p.CheckDomainDNS(context.Background(), r, "../escape", target); !errors.Is(err, ErrInvalidDomainName) {
		t.Errorf("bad domain: err = %v", err)
	}
	if _, err := p.CheckDomainDNS(context.Background(), r, "missing.example", target); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("missing domain: err = %v", err)
	}
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CheckDomainDNS(context.Background(), r, "example.com", DNSTarget{}); err == nil {
		t.Error("empty target hostname: want error")
	}
}

// TestDKIMTXTEquivalent covers the tag-level comparison: whitespace and tag
// order differences in the published record must not produce false alarms.
func TestDKIMTXTEquivalent(t *testing.T) {
	expected := "v=DKIM1; k=ed25519; p=2z+N4H4Xn=="
	for _, published := range []string{
		"v=DKIM1; k=ed25519; p=2z+N4H4Xn==",
		"v=DKIM1;k=ed25519;p=2z+N4H4Xn==",
		"v=DKIM1; p=2z+N4H4Xn==; k=ed25519",
		" v=DKIM1 ; k=ed25519 ; p=2z+N4H4Xn== ",
	} {
		if !dkimTXTEquivalent(expected, published) {
			t.Errorf("dkimTXTEquivalent(%q) = false, want true", published)
		}
	}
	for _, published := range []string{
		"v=DKIM1; k=ed25519; p=DIFFERENT==",
		"v=DKIM1; k=rsa; p=2z+N4H4Xn==",
		"not a dkim record",
	} {
		if dkimTXTEquivalent(expected, published) {
			t.Errorf("dkimTXTEquivalent(%q) = true, want false", published)
		}
	}
}

func TestCheckDomainDNS_ResolverFailureMessage(t *testing.T) {
	p, rec := dnsTestPaths(t)
	r := goodResolver("sel1", rec.DNSValue)
	delete(r.txts, "_dmarc.example.com")

	checks, err := p.CheckDomainDNS(context.Background(), r, "example.com",
		DNSTarget{Hostname: "mail.example.net", IP: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	dmarc := checksByType(checks)["dmarc"]
	if dmarc.Status != DNSStatusError {
		t.Errorf("missing dmarc: status %q, want error", dmarc.Status)
	}
	if !strings.Contains(dmarc.Message, "_dmarc.example.com") {
		t.Errorf("dmarc message should name the record location, got %q", dmarc.Message)
	}
	if !strings.Contains(dmarc.Message, fmt.Sprintf("postmaster@%s", "example.com")) {
		t.Errorf("dmarc message should suggest a rua target, got %q", dmarc.Message)
	}
}
