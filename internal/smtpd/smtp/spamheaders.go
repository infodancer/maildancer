package smtp

import (
	"sort"
	"strings"
)

// Spam-verdict headers on ingress.
//
// These are **advisory**. They exist for the recipient's own client-side filters
// and for human inspection; they are deliberately not the input to any
// server-side policy. Server-side filing acts on the verdict carried out of band
// on the delivery channel, whose provenance we control, because an in-band label
// rides in on data the sender chose and cannot be trusted for that
// (docs/spam-verdict-and-filing.md, maildancer#133).
//
// A consequence worth stating plainly, since it looks like an oversight: an
// inbound message may already carry its own X-Spam-* fields, and they are left
// in place. Ours are prepended above them, so a reader taking the topmost field
// gets our verdict, but a client-side rule matching on any field with that name
// can still see the sender's. Stripping them would mean rewriting a message we
// are about to store, which interacts badly with ARC, S/MIME and PGP
// protected-headers -- and it would only paper over the forgeability rather than
// fix it. The out-of-band verdict is the fix; these stay advisory.

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
