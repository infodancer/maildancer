package handlers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"log/slog"

	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// DNSCheckResult is the result of a single DNS record check. The check
// logic lives in internal/admin (shared with userctl); this alias keeps the
// webadmin JSON contract in one place.
type DNSCheckResult = admin.DNSCheck

// DNSHandler manages DNS record checking for domains.
type DNSHandler struct {
	domainsPath     string
	sessions        *session.Store
	logger          *slog.Logger
	settingsHandler *SettingsHandler
	resolver        admin.Resolver // nil = default resolver
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

// paths returns the admin Paths view of the handler's domain tree. The DNS
// checks only touch the config volume, so Data mirrors Config.
func (h *DNSHandler) paths() admin.Paths {
	return admin.Paths{Config: h.domainsPath, Data: h.domainsPath}
}

// HandleCheckDNSRecord checks a single DNS record type and returns JSON.
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
	target := admin.DNSTarget{Hostname: hostname, IP: ip}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resolver := h.checkResolver()
	var result DNSCheckResult
	switch recordType {
	case "a":
		result = admin.CheckDNSA(ctx, resolver, domain, ip)
	case "mx":
		result = admin.CheckDNSMX(ctx, resolver, domain, target)
	case "ptr":
		result = admin.CheckDNSPTR(ctx, resolver, target)
	case "spf":
		result = admin.CheckSPFDirect(ctx, resolver, domain, ip)
	case "dkim":
		result = h.paths().CheckDNSDKIM(ctx, resolver, domain)
	case "dmarc":
		result = admin.CheckDNSDMARC(ctx, resolver, domain)
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

	// Get the mail server hostname and IP from settings.
	hostname := ""
	ip := ""
	if h.settingsHandler != nil {
		if cfg, err := h.settingsHandler.loadSettings(); err == nil && cfg.Server.Hostname != "" {
			hostname = cfg.Server.Hostname
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if addrs, err := h.checkResolver().LookupHost(ctx, hostname); err == nil && len(addrs) > 0 {
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

	resolver := h.checkResolver()
	mx := admin.CheckDNSMX(ctx, resolver, domain, admin.DNSTarget{Hostname: hostname, IP: ip})
	spf := admin.CheckSPFDirect(ctx, resolver, domain, ip)

	// Aggregate: worst status wins.
	status := admin.DNSStatusOK
	if mx.Status == admin.DNSStatusWarning || spf.Status == admin.DNSStatusWarning {
		status = admin.DNSStatusWarning
	}
	if mx.Status == admin.DNSStatusError || spf.Status == admin.DNSStatusError {
		status = admin.DNSStatusError
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch status {
	case admin.DNSStatusOK:
		fmt.Fprint(w, `<kbd class="badge badge-yes" title="MX and SPF OK">&#10003;</kbd>`)
	case admin.DNSStatusWarning:
		fmt.Fprint(w, `<kbd class="badge badge-warn" title="DNS needs attention">&#9679;</kbd>`)
	default:
		fmt.Fprint(w, `<kbd class="badge badge-err" title="DNS records missing or incorrect">&#10007;</kbd>`)
	}
}

// checkResolver returns the handler's resolver, or the default if nil.
func (h *DNSHandler) checkResolver() admin.Resolver {
	if h.resolver != nil {
		return h.resolver
	}
	return net.DefaultResolver
}
