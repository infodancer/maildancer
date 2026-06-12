package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
)

// Resolver is the subset of *net.Resolver the DNS checks use; it exists so
// tests can substitute a fake. A nil Resolver means net.DefaultResolver.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DNS check statuses.
const (
	DNSStatusOK      = "ok"
	DNSStatusWarning = "warning"
	DNSStatusError   = "error"
)

// DNSCheck is the result of a single DNS record check.
type DNSCheck struct {
	Type     string `json:"type"`     // a, mx, ptr, spf, dkim, dmarc
	Status   string `json:"status"`   // ok, warning, error
	Expected string `json:"expected"` // what the record should be
	Actual   string `json:"actual"`   // what was found
	Message  string `json:"message"`  // human-readable explanation
}

// DNSTarget is the mail server identity the domain's DNS records should
// reference: the hostname MX and PTR point at, and the outbound IP SPF
// authorizes. IP may be empty, in which case IP-dependent checks degrade
// to warnings instead of guessing.
type DNSTarget struct {
	Hostname string
	IP       string
}

// ErrDNSTargetRequired is returned when no server hostname could be resolved
// from flags or configuration.
var ErrDNSTargetRequired = errors.New("server hostname required for DNS checks")

// CheckDomainDNS runs all DNS checks for the domain against the target
// server identity, in the order a, mx, ptr, spf, dkim, dmarc. The SPF check
// is smarthost-aware (per the domain's outbound config) and the DKIM check
// compares the published record against the domain's configured key.
func (p Paths) CheckDomainDNS(ctx context.Context, r Resolver, domainName string, target DNSTarget) ([]DNSCheck, error) {
	if !ValidDomainName(domainName) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domainName) {
		return nil, ErrDomainNotFound
	}
	if target.Hostname == "" {
		return nil, ErrDNSTargetRequired
	}
	if r == nil {
		r = net.DefaultResolver
	}

	cfg, err := domain.LoadDomainConfig(filepath.Join(p.Config, domainName, "config.toml"))
	if err != nil {
		cfg = &domain.DomainConfig{}
	}

	var spf DNSCheck
	if cfg.Outbound.Strategy == "smarthost" {
		spf = CheckSPFSmarthost(ctx, r, domainName, cfg.Outbound.Smarthost)
	} else {
		spf = CheckSPFDirect(ctx, r, domainName, target.IP)
	}

	return []DNSCheck{
		CheckDNSA(ctx, r, domainName, target.IP),
		CheckDNSMX(ctx, r, domainName, target),
		CheckDNSPTR(ctx, r, target),
		spf,
		p.CheckDNSDKIM(ctx, r, domainName),
		CheckDNSDMARC(ctx, r, domainName),
	}, nil
}

// CheckDNSA verifies the domain's A/AAAA record resolves to the expected IP.
func CheckDNSA(ctx context.Context, r Resolver, domainName, expectedIP string) DNSCheck {
	result := DNSCheck{Type: "a"}
	if expectedIP == "" {
		result.Status = DNSStatusWarning
		result.Message = "No server IP available; cannot verify the A record. Set dns.public_ip or pass --ip."
		return result
	}
	result.Expected = fmt.Sprintf("%s -> %s", domainName, expectedIP)

	addrs, err := r.LookupHost(ctx, domainName)
	if err != nil {
		result.Status = DNSStatusError
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No A/AAAA record found for %s. Create an A record pointing to %s.", domainName, expectedIP)
		return result
	}

	result.Actual = strings.Join(addrs, ", ")
	for _, addr := range addrs {
		if addr == expectedIP {
			result.Status = DNSStatusOK
			result.Message = fmt.Sprintf("%s resolves to %s.", domainName, expectedIP)
			return result
		}
	}

	result.Status = DNSStatusWarning
	result.Message = fmt.Sprintf("%s resolves to %s, not %s. Update the A record to point to your mail server.", domainName, result.Actual, expectedIP)
	return result
}

// CheckDNSMX verifies the domain's MX points at the mail server, matching
// either by hostname or by the address an MX host resolves to.
func CheckDNSMX(ctx context.Context, r Resolver, domainName string, target DNSTarget) DNSCheck {
	result := DNSCheck{
		Type:     "mx",
		Expected: fmt.Sprintf("MX for %s -> %s", domainName, target.Hostname),
	}

	mxRecords, err := r.LookupMX(ctx, domainName)
	if err != nil || len(mxRecords) == 0 {
		result.Status = DNSStatusError
		result.Actual = "no MX records"
		result.Message = fmt.Sprintf("No MX records found for %s. Create an MX record (e.g., 10 %s).", domainName, target.Hostname)
		return result
	}

	var mxHosts []string
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		mxHosts = append(mxHosts, host)
		if strings.EqualFold(host, target.Hostname) {
			result.Status = DNSStatusOK
			result.Actual = strings.Join(mxHosts, ", ")
			result.Message = fmt.Sprintf("MX for %s is %s.", domainName, host)
			return result
		}
		if target.IP == "" {
			continue
		}
		addrs, err := r.LookupHost(ctx, mx.Host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr == target.IP {
				result.Status = DNSStatusOK
				result.Actual = strings.Join(mxHosts, ", ")
				result.Message = fmt.Sprintf("MX host %s resolves to %s.", host, target.IP)
				return result
			}
		}
	}

	result.Status = DNSStatusWarning
	result.Actual = strings.Join(mxHosts, ", ")
	result.Message = fmt.Sprintf("MX records exist (%s) but none match %s.", result.Actual, target.Hostname)
	return result
}

// CheckDNSPTR verifies reverse DNS of the server IP matches the hostname.
func CheckDNSPTR(ctx context.Context, r Resolver, target DNSTarget) DNSCheck {
	result := DNSCheck{Type: "ptr"}
	if target.IP == "" {
		result.Status = DNSStatusWarning
		result.Message = "No server IP available; cannot verify reverse DNS. Set dns.public_ip or pass --ip."
		return result
	}
	result.Expected = fmt.Sprintf("%s -> %s", target.IP, target.Hostname)

	names, err := r.LookupAddr(ctx, target.IP)
	if err != nil || len(names) == 0 {
		result.Status = DNSStatusError
		result.Actual = "no PTR record"
		result.Message = fmt.Sprintf("No reverse DNS (PTR) record for %s. Contact your hosting provider to set PTR to %s.", target.IP, target.Hostname)
		return result
	}

	var ptrNames []string
	for _, name := range names {
		clean := strings.TrimSuffix(name, ".")
		ptrNames = append(ptrNames, clean)
		if strings.EqualFold(clean, target.Hostname) {
			result.Status = DNSStatusOK
			result.Actual = clean
			result.Message = fmt.Sprintf("Reverse DNS for %s is %s.", target.IP, clean)
			return result
		}
	}

	result.Status = DNSStatusWarning
	result.Actual = strings.Join(ptrNames, ", ")
	result.Message = fmt.Sprintf("PTR for %s is %s, not %s. Contact your provider to update.", target.IP, result.Actual, target.Hostname)
	return result
}

// lookupSPF returns the domain's SPF TXT record, or "" if none exists.
func lookupSPF(ctx context.Context, r Resolver, domainName string) (string, error) {
	txts, err := r.LookupTXT(ctx, domainName)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt, nil
		}
	}
	return "", nil
}

// CheckSPFDirect verifies the domain's SPF record covers the server's
// outbound IP. Mechanism evaluation is heuristic (direct ip4:/ip6: match);
// include: indirection produces a warning, not a pass.
func CheckSPFDirect(ctx context.Context, r Resolver, domainName, expectedIP string) DNSCheck {
	result := DNSCheck{Type: "spf"}
	if expectedIP == "" {
		result.Status = DNSStatusWarning
		result.Message = "No server IP available; cannot verify SPF coverage. Set dns.public_ip or pass --ip."
		return result
	}
	result.Expected = fmt.Sprintf("v=spf1 ... ip4:%s ... -all", expectedIP)

	txt, err := lookupSPF(ctx, r, domainName)
	if err != nil || txt == "" {
		result.Status = DNSStatusError
		result.Actual = "no SPF record"
		result.Message = fmt.Sprintf("No SPF record found. Add a TXT record: v=spf1 ip4:%s -all", expectedIP)
		return result
	}

	result.Actual = txt
	ipMech := "ip4:" + expectedIP
	if strings.Contains(expectedIP, ":") {
		ipMech = "ip6:" + expectedIP
	}
	if strings.Contains(txt, ipMech) || strings.Contains(txt, "+all") {
		result.Status = DNSStatusOK
		result.Message = "SPF record includes your mail server IP."
		return result
	}

	result.Status = DNSStatusWarning
	result.Message = fmt.Sprintf("SPF record exists but does not directly include %s. It may be covered by an include: or a: mechanism; verify manually.", expectedIP)
	return result
}

// CheckSPFSmarthost verifies a smarthost-routed domain has an SPF record.
// Whether the record covers the smarthost cannot be evaluated mechanically
// (the right mechanism is the relay operator's to specify), so an existing
// record is reported as a warning asking the operator to confirm coverage.
func CheckSPFSmarthost(ctx context.Context, r Resolver, domainName, smarthost string) DNSCheck {
	host := smarthost
	if h, _, err := net.SplitHostPort(smarthost); err == nil {
		host = h
	}
	result := DNSCheck{
		Type:     "spf",
		Expected: fmt.Sprintf("v=spf1 record covering smarthost %s", host),
	}

	txt, err := lookupSPF(ctx, r, domainName)
	if err != nil || txt == "" {
		result.Status = DNSStatusError
		result.Actual = "no SPF record"
		result.Message = fmt.Sprintf("No SPF record found. This domain relays through %s; add the SPF mechanism your relay operator specifies (often an include:).", host)
		return result
	}

	result.Status = DNSStatusWarning
	result.Actual = txt
	result.Message = fmt.Sprintf("This domain relays through %s. Confirm the SPF record covers it (typically via the include: your relay operator specifies).", host)
	return result
}

// CheckDNSDKIM compares the published DKIM record for the domain's
// configured selector against the local key. When no local DKIM key is
// configured the check is a warning, since there is nothing to compare.
func (p Paths) CheckDNSDKIM(ctx context.Context, r Resolver, domainName string) DNSCheck {
	result := DNSCheck{Type: "dkim"}

	rec, err := p.DKIMStatus(domainName)
	if err != nil {
		result.Status = DNSStatusWarning
		if errors.Is(err, ErrDKIMNotConfigured) {
			result.Message = fmt.Sprintf("No local DKIM key configured for %s; run: userctl domain dkim create %s", domainName, domainName)
		} else {
			result.Message = fmt.Sprintf("Cannot load local DKIM key: %v", err)
		}
		return result
	}

	result.Expected = fmt.Sprintf("TXT at %s: %s", rec.DNSName, rec.DNSValue)

	txts, err := r.LookupTXT(ctx, rec.DNSName)
	if err != nil || len(txts) == 0 {
		result.Status = DNSStatusError
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No DKIM record found at %s. Publish: %s", rec.DNSName, rec.DNSValue)
		return result
	}

	for _, txt := range txts {
		if dkimTXTEquivalent(rec.DNSValue, txt) {
			result.Status = DNSStatusOK
			result.Actual = txt
			result.Message = "DKIM record matches the local key."
			return result
		}
	}

	result.Status = DNSStatusError
	result.Actual = txts[0]
	result.Message = fmt.Sprintf("DKIM record at %s does not match the local key. Publish: %s", rec.DNSName, rec.DNSValue)
	return result
}

// dkimTXTEquivalent compares two DKIM TXT records at the tag level, so
// whitespace and tag-order differences do not produce false alarms.
func dkimTXTEquivalent(expected, published string) bool {
	want := dkimTags(expected)
	got := dkimTags(published)
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// dkimTags parses a DKIM TXT record into a tag=value map.
func dkimTags(record string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		tags[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return tags
}

// CheckDNSDMARC checks for a DMARC TXT record at _dmarc.{domain}.
func CheckDNSDMARC(ctx context.Context, r Resolver, domainName string) DNSCheck {
	dmarcDomain := "_dmarc." + domainName
	result := DNSCheck{
		Type:     "dmarc",
		Expected: fmt.Sprintf("TXT at %s with v=DMARC1", dmarcDomain),
	}

	txts, err := r.LookupTXT(ctx, dmarcDomain)
	if err != nil || len(txts) == 0 {
		result.Status = DNSStatusError
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No DMARC record found. Add a TXT record at %s: v=DMARC1; p=quarantine; rua=mailto:postmaster@%s", dmarcDomain, domainName)
		return result
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			result.Status = DNSStatusOK
			result.Actual = txt
			result.Message = "DMARC record found."
			return result
		}
	}

	result.Status = DNSStatusWarning
	result.Actual = txts[0]
	result.Message = fmt.Sprintf("TXT record exists at %s but does not start with v=DMARC1.", dmarcDomain)
	return result
}
