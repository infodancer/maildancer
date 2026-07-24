package rspamd

import (
	"strings"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// RFC 8601 Authentication-Results, derived from rspamd's verdicts.
//
// smtpd deliberately does not verify SPF, DKIM, or DMARC itself. rspamd already
// runs all three on every message it scores, so this translates the symbols it
// reports into the standard header rather than duplicating the verification (and
// the second, subtly different set of bugs that would come with it).

// authResultsHeader is the RFC 8601 header field name.
const authResultsHeader = "Authentication-Results"

// maxPropertyValue bounds a single property value (a domain, a selector). These
// come from the message, so they are attacker-controlled; see sanitizeProperty.
const maxPropertyValue = 255

// symbolResult pairs an rspamd symbol with the RFC 8601 result keyword it means.
type symbolResult struct {
	symbol string
	result string
}

// methodMapping describes how one RFC 8601 authentication method is recovered
// from rspamd's symbols. Symbols are tested in order and the first match wins,
// so more specific verdicts must precede more general ones.
type methodMapping struct {
	method  string // RFC 8601 method name: "spf", "dkim", "dmarc", "arc"
	symbols []symbolResult
}

// authMethods lists the methods we report, in the order they are emitted. The
// symbol names are rspamd's defaults (SPF, DKIM, DMARC, and ARC modules are all
// enabled out of the box), so this works against a stock rspamd with no
// configuration on the rspamd side.
var authMethods = []methodMapping{
	{
		method: "spf",
		symbols: []symbolResult{
			{"R_SPF_ALLOW", "pass"},
			{"R_SPF_FAIL", "fail"},
			{"R_SPF_SOFTFAIL", "softfail"},
			{"R_SPF_NEUTRAL", "neutral"},
			{"R_SPF_DNSFAIL", "temperror"},
			{"R_SPF_PERMFAIL", "permerror"},
			{"R_SPF_NA", "none"},
		},
	},
	{
		method: "dkim",
		symbols: []symbolResult{
			{"R_DKIM_ALLOW", "pass"},
			{"R_DKIM_REJECT", "fail"},
			{"R_DKIM_TEMPFAIL", "temperror"},
			{"R_DKIM_PERMFAIL", "permerror"},
			{"R_DKIM_NA", "none"},
		},
	},
	{
		method: "dmarc",
		symbols: []symbolResult{
			// A quarantine or reject policy both mean DMARC evaluation failed;
			// RFC 7489 section 7.1 maps the policy applied, not the disposition,
			// so all three failure policies report "fail".
			{"DMARC_POLICY_ALLOW", "pass"},
			{"DMARC_POLICY_REJECT", "fail"},
			{"DMARC_POLICY_QUARANTINE", "fail"},
			{"DMARC_POLICY_SOFTFAIL", "fail"},
			{"DMARC_BAD_POLICY", "permerror"},
			{"DMARC_DNSFAIL", "temperror"},
			{"DMARC_NA", "none"},
		},
	},
	{
		method: "arc",
		symbols: []symbolResult{
			{"ARC_ALLOW", "pass"},
			{"ARC_REJECT", "fail"},
			{"ARC_INVALID", "permerror"},
			{"ARC_DNSFAIL", "temperror"},
			{"ARC_NA", "none"},
		},
	},
}

// buildAuthResults renders the Authentication-Results field *value* -- everything
// after "Authentication-Results: " -- for a scored message, folded with tab
// continuation lines and with no trailing CRLF.
//
// It returns "" when there is nothing trustworthy to say: no authserv-id (an
// RFC 8601 header without one identifies no ADMD and cannot be evaluated), or no
// authentication symbols at all. Stamping an empty verdict would assert that we
// checked and found nothing, which is not the same as not having checked.
func buildAuthResults(r *RspamdResult, opts spamcheck.CheckOptions) string {
	authserv := sanitizeProperty(opts.Hostname)
	if authserv == "" || r == nil {
		return ""
	}

	// rspamd can be configured to emit the header itself (milter_headers with
	// the authentication-results routine). When it does, prefer it: it is
	// assembled from the full verification state rather than reconstructed from
	// symbol names. It still passes through sanitizeHeaderValue because the
	// domains inside it come from the message.
	if r.Milter != nil {
		for name, hv := range r.Milter.AddHeaders {
			if strings.EqualFold(name, authResultsHeader) {
				if v := sanitizeHeaderValue(hv.Value); v != "" {
					return v
				}
			}
		}
	}

	var methods []string
	for _, m := range authMethods {
		result, sym, ok := m.evaluate(r.Symbols)
		if !ok {
			continue
		}
		clause := m.method + "=" + result
		if prop := propertyFor(m.method, sym, opts); prop != "" {
			clause += " " + prop
		}
		methods = append(methods, clause)
	}
	if len(methods) == 0 {
		return ""
	}

	return authserv + ";\r\n\t" + strings.Join(methods, ";\r\n\t")
}

// evaluate returns the RFC 8601 result keyword for this method, along with the
// matching symbol, or ok=false when rspamd reported none of its symbols.
func (m methodMapping) evaluate(symbols map[string]SymbolResult) (string, SymbolResult, bool) {
	for _, sr := range m.symbols {
		if sym, present := symbols[sr.symbol]; present {
			return sr.result, sym, true
		}
	}
	return "", SymbolResult{}, false
}

// propertyFor renders the RFC 8601 "ptype.property=value" clause that identifies
// what a method actually authenticated, or "" when the value is unavailable.
// Omitting the property is always safe; inventing one is not.
func propertyFor(method string, sym SymbolResult, opts spamcheck.CheckOptions) string {
	switch method {
	case "spf":
		// RFC 7208: SPF checks the envelope sender, falling back to the HELO
		// identity for a null return-path (bounces).
		if d := domainOf(opts.From); d != "" {
			return "smtp.mailfrom=" + sanitizeProperty(d)
		}
		if h := sanitizeProperty(opts.Helo); h != "" {
			return "smtp.helo=" + h
		}
	case "dkim":
		// rspamd reports the signing identity as "domain" or "domain:s=selector".
		if d := sanitizeProperty(firstOption(sym)); d != "" {
			domain, selector, hasSelector := strings.Cut(d, ":")
			if !hasSelector {
				return "header.d=" + domain
			}
			return "header.d=" + domain + " " + strings.Replace(selector, "s=", "header.s=", 1)
		}
	case "dmarc":
		// DMARC is evaluated against the RFC 5322 From domain, which rspamd
		// reports as the symbol's first option.
		if d := sanitizeProperty(firstOption(sym)); d != "" {
			return "header.from=" + d
		}
	}
	return ""
}

// firstOption returns the symbol's first option, or "".
func firstOption(sym SymbolResult) string {
	if len(sym.Options) == 0 {
		return ""
	}
	return sym.Options[0]
}

// domainOf returns the domain part of an address, or "" if there is none. The
// envelope sender is empty for a bounce, which is not an error here.
func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return addr[i+1:]
	}
	return ""
}

// sanitizeProperty reduces an untrusted value to characters that cannot break
// out of a header field: no CR, LF, whitespace, semicolon, or non-ASCII. Every
// value reaching here originates in the message or the SMTP envelope, so a
// domain of "example.com\r\nAuthentication-Results: ..." must not become two
// headers. Anything unusable is dropped rather than escaped, and the result is
// truncated to maxPropertyValue.
func sanitizeProperty(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < '!' || r > '~' || r == ';' {
			continue
		}
		if b.Len() >= maxPropertyValue {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sanitizeHeaderValue cleans a whole field value supplied by rspamd. Unlike
// sanitizeProperty it must keep the structural characters (spaces, semicolons)
// that make the value parseable, so it only removes the ones that would inject a
// new header field, and refolds nothing.
func sanitizeHeaderValue(v string) string {
	v = strings.NewReplacer("\r", "", "\n", "").Replace(v)
	var b strings.Builder
	for _, r := range v {
		if r != '\t' && (r < ' ' || r > '~') {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
