package smtp

import (
	"sort"
	"strings"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// canonicalSpamHeaderOrder fixes the emission order of the well-known X-Spam-*
// fields so the stamped block is deterministic (tests, and readers scanning a
// stable layout). Any headers not listed here follow, sorted by name.
var canonicalSpamHeaderOrder = []string{
	"X-Spam-Flag",
	"X-Spam-Status",
	"X-Spam-Score",
	"X-Spam-Checker",
}

// buildSpamHeaders renders the spam-check verdict headers (X-Spam-Flag,
// X-Spam-Status, ...) computed by the checker into a CRLF-terminated header
// block suitable for prepending above the Received trace header. Without this
// the headers are computed and discarded -- no delivered message carries
// X-Spam-Flag, so the delivery pipeline's default spam-to-Junk rule and the
// user's own client-side filters have nothing to act on (maildancer#133).
//
// Returns "" when header stamping is disabled (add == false), there is no
// result, or the result carried no headers. CR/LF are stripped from every name
// and value to prevent header injection from a compromised or malformed checker
// response.
func buildSpamHeaders(result *spamcheck.CheckResult, add bool) string {
	if !add || result == nil || len(result.Headers) == 0 {
		return ""
	}

	// Emit the canonical fields first (in fixed order), then any extras sorted.
	emitted := make(map[string]bool, len(result.Headers))
	names := make([]string, 0, len(result.Headers))
	for _, name := range canonicalSpamHeaderOrder {
		if _, ok := result.Headers[name]; ok {
			names = append(names, name)
			emitted[name] = true
		}
	}
	extras := make([]string, 0, len(result.Headers))
	for name := range result.Headers {
		if !emitted[name] {
			extras = append(extras, name)
		}
	}
	sort.Strings(extras)
	names = append(names, extras...)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(sanitizeHeaderField(name))
		b.WriteString(": ")
		b.WriteString(sanitizeHeaderField(result.Headers[name]))
		b.WriteString("\r\n")
	}
	return b.String()
}

// sanitizeHeaderField removes CR and LF so a header value cannot inject
// additional header lines or a premature end-of-headers.
func sanitizeHeaderField(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
