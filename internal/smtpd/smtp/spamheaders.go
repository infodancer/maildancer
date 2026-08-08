package smtp

import (
	"sort"
	"strings"
)

// Spam-verdict headers on ingress.
//
// The scan happens in smtpd, but the decision about what to do with a
// non-rejected verdict does not belong here: where borderline mail goes is
// per-user policy, expressed in Sieve at delivery time (maildancer#133). These
// headers are the only channel between the two -- a Sieve script sees the
// message bytes and nothing else -- so what is stamped here is an interface,
// not a diagnostic.
//
// That makes them worth the same care as Authentication-Results: a verdict is
// only worth anything if it cannot be forged, so inbound X-Spam-* fields are
// removed before ours are added (see stripStampedHeaders).

// spamHeaderPrefix is the field-name prefix we own on a delivered message,
// lowercased for direct comparison against a line prefix.
const spamHeaderPrefix = "x-spam-"

// leadingSpamHeaders are rendered first, in this order, so the block reads the
// same way on every message. The most useful field for a hand-written Sieve
// rule leads; the rest follow in decreasing order of how often a script would
// reference them. Any field not listed here is rendered afterwards, sorted, so
// the output never depends on map iteration order.
var leadingSpamHeaders = []string{
	"X-Spam-Flag",
	"X-Spam-Value",
	"X-Spam-Score",
	"X-Spam-Status",
	"X-Spam-Checker",
}

// buildSpamHeaders renders spam-verdict fields as a header block ending in CRLF,
// or "" when there is nothing to stamp so callers can concatenate it
// unconditionally.
//
// Names and values are constrained rather than trusted. They originate with the
// checker, and rspamd's milter add_headers carries operator- and rule-supplied
// strings, so a value containing CRLF would otherwise terminate the field and
// let the remainder be read as a header of its own -- including a second
// X-Spam-Flag that a Sieve rule might match instead of ours.
func buildSpamHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	rendered := make(map[string]bool, len(headers))
	var b strings.Builder

	write := func(name string) {
		value, ok := headers[name]
		if !ok || rendered[name] {
			return
		}
		rendered[name] = true
		cleanName, ok := sanitizeFieldName(name)
		if !ok {
			return
		}
		b.WriteString(cleanName)
		b.WriteString(": ")
		b.WriteString(sanitizeFieldValue(value))
		b.WriteString("\r\n")
	}

	for _, name := range leadingSpamHeaders {
		write(name)
	}

	rest := make([]string, 0, len(headers))
	for name := range headers {
		if !rendered[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		write(name)
	}

	return b.String()
}

// sanitizeFieldName reports whether name is usable as an RFC 5322 field name and
// returns it unchanged if so. A bad name is rejected rather than repaired:
// stripping the offending bytes could turn a malformed key into a different,
// well-known field, which is a worse outcome than dropping it.
func sanitizeFieldName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	// RFC 5322 field-name: printable US-ASCII except colon.
	for _, r := range name {
		if r < '!' || r > '~' || r == ':' {
			return "", false
		}
	}
	return name, true
}

// sanitizeFieldValue removes everything that could end the field or introduce a
// new one. Unlike the name, a value is cleaned rather than dropped: losing a
// verdict entirely because rspamd emitted an odd byte is worse than stamping the
// printable remainder.
func sanitizeFieldValue(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r == '\r' || r == '\n' {
			// A space, not nothing: removing the break outright would weld the
			// tokens either side together ("NO" + "X-Spam-Value: 1" reading as
			// "NOX-Spam-Value: 1"), which is inert but reads like a field name
			// and invites a second look every time it appears in a log.
			b.WriteByte(' ')
			continue
		}
		if r != '\t' && (r < ' ' || r > '~') {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// isSpamHeaderLine reports whether a header line starts a field we stamp
// ourselves, and whose inbound copy must therefore be removed.
func isSpamHeaderLine(line []byte) bool {
	if len(line) < len(spamHeaderPrefix) {
		return false
	}
	return strings.EqualFold(string(line[:len(spamHeaderPrefix)]), spamHeaderPrefix)
}
