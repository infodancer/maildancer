package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// DNSCheckResult holds the result of a single DNS record check.
type DNSCheckResult struct {
	Type     string `json:"type"`     // a, mx, ptr, spf, dkim, dmarc
	Status   string `json:"status"`   // ok, warning, error
	Expected string `json:"expected"` // what the record should be
	Actual   string `json:"actual"`   // what was found
	Message  string `json:"message"`  // human-readable explanation
}

// DNSHandler manages DNS record checking for domains.
type DNSHandler struct {
	domainsPath     string
	sessions        *session.Store
	logger          *slog.Logger
	settingsHandler *SettingsHandler
	resolver        *net.Resolver // nil = default resolver
}

// NewDNSHandler creates a new DNSHandler.
func NewDNSHandler(domainsPath string, sessions *session.Store, logger *slog.Logger, sh *SettingsHandler) *DNSHandler {
	return &DNSHandler{
		domainsPath:     domainsPath,
		sessions:        sessions,
		logger:          logger,
		settingsHandler: sh,
	}
}

// HandleCheckDNSRecord checks a single DNS record type and returns an HTML partial.
func (h *DNSHandler) HandleCheckDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	recordType := r.URL.Query().Get("type")
	ip := r.URL.Query().Get("ip")
	hostname := r.URL.Query().Get("hostname")

	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip parameter is required"})
		return
	}
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}
	if hostname == "" {
		hostname = domain
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var result DNSCheckResult
	switch recordType {
	case "a":
		result = checkA(ctx, h.resolver, domain, ip)
	case "mx":
		result = checkMX(ctx, h.resolver, domain, ip)
	case "ptr":
		result = checkPTR(ctx, h.resolver, hostname, ip)
	case "spf":
		result = checkSPF(ctx, h.resolver, domain, ip)
	case "dkim":
		result = checkDKIM(ctx, h.resolver, domain)
	case "dmarc":
		result = checkDMARC(ctx, h.resolver, domain)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be one of: a, mx, ptr, spf, dkim, dmarc"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// HandleDNSStatus returns an aggregate DNS status for the dashboard indicator.
// Checks MX and SPF as a lightweight subset.
func (h *DNSHandler) HandleDNSStatus(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("name")
	if !isValidDomainName(domain) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<kbd class="badge badge-no">?</kbd>`)
		return
	}

	// Get the mail server IP from settings.
	ip := ""
	if h.settingsHandler != nil {
		if cfg, err := h.settingsHandler.loadSettings(); err == nil && cfg.Server.Hostname != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if addrs, err := resolverFor(h.resolver).LookupHost(ctx, cfg.Server.Hostname); err == nil && len(addrs) > 0 {
				ip = addrs[0]
			}
		}
	}

	if ip == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<kbd class="badge badge-warn" title="Configure server hostname in settings to enable DNS checks">?</kbd>`)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	mx := checkMX(ctx, h.resolver, domain, ip)
	spf := checkSPF(ctx, h.resolver, domain, ip)

	// Aggregate: worst status wins.
	status := "ok"
	if mx.Status == "warning" || spf.Status == "warning" {
		status = "warning"
	}
	if mx.Status == "error" || spf.Status == "error" {
		status = "error"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch status {
	case "ok":
		fmt.Fprint(w, `<kbd class="badge badge-yes" title="MX and SPF OK">&#10003;</kbd>`)
	case "warning":
		fmt.Fprint(w, `<kbd class="badge badge-warn" title="DNS needs attention">&#9679;</kbd>`)
	default:
		fmt.Fprint(w, `<kbd class="badge badge-err" title="DNS records missing or incorrect">&#10007;</kbd>`)
	}
}

// resolverFor returns the given resolver, or the default if nil.
func resolverFor(r *net.Resolver) *net.Resolver {
	if r != nil {
		return r
	}
	return net.DefaultResolver
}

// checkA verifies that the domain's A record resolves to the expected IP.
func checkA(ctx context.Context, resolver *net.Resolver, domain, expectedIP string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "a",
		Expected: fmt.Sprintf("%s -> %s", domain, expectedIP),
	}

	addrs, err := resolverFor(resolver).LookupHost(ctx, domain)
	if err != nil {
		result.Status = "error"
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No A/AAAA record found for %s. Create an A record pointing to %s.", domain, expectedIP)
		return result
	}

	result.Actual = strings.Join(addrs, ", ")
	for _, addr := range addrs {
		if addr == expectedIP {
			result.Status = "ok"
			result.Message = fmt.Sprintf("%s resolves to %s.", domain, expectedIP)
			return result
		}
	}

	result.Status = "warning"
	result.Message = fmt.Sprintf("%s resolves to %s, not %s. Update the A record to point to your mail server.", domain, result.Actual, expectedIP)
	return result
}

// checkMX verifies that the domain's MX record points to a host resolving to the expected IP.
func checkMX(ctx context.Context, resolver *net.Resolver, domain, expectedIP string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "mx",
		Expected: fmt.Sprintf("MX for %s -> host resolving to %s", domain, expectedIP),
	}

	r := resolverFor(resolver)
	mxRecords, err := r.LookupMX(ctx, domain)
	if err != nil || len(mxRecords) == 0 {
		result.Status = "error"
		result.Actual = "no MX records"
		result.Message = fmt.Sprintf("No MX records found for %s. Create an MX record (e.g., 10 mail.%s).", domain, domain)
		return result
	}

	var mxHosts []string
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		mxHosts = append(mxHosts, host)
		addrs, err := r.LookupHost(ctx, mx.Host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr == expectedIP {
				result.Status = "ok"
				result.Actual = strings.Join(mxHosts, ", ")
				result.Message = fmt.Sprintf("MX host %s resolves to %s.", host, expectedIP)
				return result
			}
		}
	}

	result.Status = "warning"
	result.Actual = strings.Join(mxHosts, ", ")
	result.Message = fmt.Sprintf("MX records exist (%s) but none resolve to %s.", result.Actual, expectedIP)
	return result
}

// checkPTR verifies that reverse DNS of the IP matches the mail hostname.
func checkPTR(ctx context.Context, resolver *net.Resolver, hostname, ip string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "ptr",
		Expected: fmt.Sprintf("%s -> %s", ip, hostname),
	}

	names, err := resolverFor(resolver).LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		result.Status = "error"
		result.Actual = "no PTR record"
		result.Message = fmt.Sprintf("No reverse DNS (PTR) record for %s. Contact your hosting provider to set PTR to %s.", ip, hostname)
		return result
	}

	var ptrNames []string
	for _, name := range names {
		clean := strings.TrimSuffix(name, ".")
		ptrNames = append(ptrNames, clean)
		if strings.EqualFold(clean, hostname) {
			result.Status = "ok"
			result.Actual = clean
			result.Message = fmt.Sprintf("Reverse DNS for %s is %s.", ip, clean)
			return result
		}
	}

	result.Status = "warning"
	result.Actual = strings.Join(ptrNames, ", ")
	result.Message = fmt.Sprintf("PTR for %s is %s, not %s. Contact your provider to update.", ip, result.Actual, hostname)
	return result
}

// checkSPF verifies that the domain has an SPF TXT record including the mail server IP.
func checkSPF(ctx context.Context, resolver *net.Resolver, domain, expectedIP string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "spf",
		Expected: fmt.Sprintf("v=spf1 ... ip4:%s ... -all", expectedIP),
	}

	txts, err := resolverFor(resolver).LookupTXT(ctx, domain)
	if err != nil {
		result.Status = "error"
		result.Actual = "no TXT records"
		result.Message = fmt.Sprintf("No TXT records found for %s. Add an SPF record: v=spf1 ip4:%s -all", domain, expectedIP)
		return result
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=spf1") {
			continue
		}
		result.Actual = txt
		// Check if IP is directly included.
		ipMech := "ip4:" + expectedIP
		if net.ParseIP(expectedIP) != nil && strings.Contains(expectedIP, ":") {
			ipMech = "ip6:" + expectedIP
		}
		if strings.Contains(txt, ipMech) || strings.Contains(txt, "+all") {
			result.Status = "ok"
			result.Message = "SPF record includes your mail server IP."
			return result
		}
		result.Status = "warning"
		result.Message = fmt.Sprintf("SPF record exists but does not directly include %s. It may be covered by an include: mechanism.", expectedIP)
		return result
	}

	result.Status = "error"
	result.Actual = "no SPF record"
	result.Message = fmt.Sprintf("No SPF record found. Add a TXT record: v=spf1 ip4:%s -all", expectedIP)
	return result
}

// checkDKIM checks for a DKIM TXT record at default._domainkey.{domain}.
func checkDKIM(ctx context.Context, resolver *net.Resolver, domain string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "dkim",
		Expected: fmt.Sprintf("TXT at default._domainkey.%s with v=DKIM1", domain),
	}

	dkimDomain := "default._domainkey." + domain
	txts, err := resolverFor(resolver).LookupTXT(ctx, dkimDomain)
	if err != nil || len(txts) == 0 {
		result.Status = "warning"
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No DKIM record found at %s. If you use a different selector, this is expected.", dkimDomain)
		return result
	}

	for _, txt := range txts {
		if strings.Contains(txt, "v=DKIM1") {
			result.Status = "ok"
			result.Actual = txt
			if len(result.Actual) > 80 {
				result.Actual = result.Actual[:80] + "..."
			}
			result.Message = "DKIM record found."
			return result
		}
	}

	result.Status = "warning"
	result.Actual = txts[0]
	if len(result.Actual) > 80 {
		result.Actual = result.Actual[:80] + "..."
	}
	result.Message = fmt.Sprintf("TXT record exists at %s but does not contain v=DKIM1.", dkimDomain)
	return result
}

// checkDMARC checks for a DMARC TXT record at _dmarc.{domain}.
func checkDMARC(ctx context.Context, resolver *net.Resolver, domain string) DNSCheckResult {
	result := DNSCheckResult{
		Type:     "dmarc",
		Expected: fmt.Sprintf("TXT at _dmarc.%s with v=DMARC1", domain),
	}

	dmarcDomain := "_dmarc." + domain
	txts, err := resolverFor(resolver).LookupTXT(ctx, dmarcDomain)
	if err != nil || len(txts) == 0 {
		result.Status = "error"
		result.Actual = "no record"
		result.Message = fmt.Sprintf("No DMARC record found. Add a TXT record at %s: v=DMARC1; p=quarantine; rua=mailto:postmaster@%s", dmarcDomain, domain)
		return result
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			result.Status = "ok"
			result.Actual = txt
			result.Message = "DMARC record found."
			return result
		}
	}

	result.Status = "warning"
	result.Actual = txts[0]
	result.Message = fmt.Sprintf("TXT record exists at %s but does not start with v=DMARC1.", dmarcDomain)
	return result
}

// checkAll runs all DNS checks and returns results.
func checkAll(ctx context.Context, resolver *net.Resolver, domain, hostname, ip string) []DNSCheckResult {
	return []DNSCheckResult{
		checkA(ctx, resolver, domain, ip),
		checkMX(ctx, resolver, domain, ip),
		checkPTR(ctx, resolver, hostname, ip),
		checkSPF(ctx, resolver, domain, ip),
		checkDKIM(ctx, resolver, domain),
		checkDMARC(ctx, resolver, domain),
	}
}
