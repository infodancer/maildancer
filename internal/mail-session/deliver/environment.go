package deliver

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// Sieve environment items (RFC 5183).
//
// This is how a user's Sieve script reads the spam verdict. It has to be the
// environment rather than a header test, because the verdict is carried out of
// band on the delivery channel precisely so a sender cannot forge it
// (docs/spam-verdict-and-filing.md) -- and a script otherwise sees only the
// message, whose X-Spam-* fields are advisory and sender-influenced. Environment
// items come from the runtime, so they carry the same provenance guarantee as
// the verdict itself.
//
// Unsupported vs empty is a real distinction here, not a formality. RFC 5183
// section 4 makes a test against an unsupported item fail unconditionally, which
// is exactly right for "we do not know": a threshold rule does not fire rather
// than comparing against a value we invented.

// Standard item values that do not vary per message.
const (
	// envName identifies the implementation (RFC 5183 section 4.1).
	envName = "maildancer"

	// envLocation is where in the mail system the script runs. RFC 5183 defines
	// MTA, MDA, MUA and MS; Sieve runs in mail-session, the delivery agent.
	envLocation = "MDA"

	// envPhase is when relative to delivery. RFC 5183 defines pre, during and
	// post; the script runs as part of delivery.
	envPhase = "during"
)

// spamValueHeader is the checker-supplied field carrying the RFC 5235 0..10
// normalization. It is read from the verdict's header map rather than
// recomputed: the map travels with the verdict, and the inputs needed to derive
// it (notably the checker's own threshold) are not carried.
const spamValueHeader = "X-Spam-Value"

// sieveEnv implements interp.Env, supplying RFC 5183 environment items to a
// running Sieve script.
type sieveEnv struct {
	// spam is the out-of-band verdict, nil when no scan ran. The nil case
	// matters: a non-nil verdict with IsSpam false means "scanned and judged
	// clean", which is not the same statement as "not scanned".
	spam *SpamVerdict
}

func newSieveEnv(spam *SpamVerdict) *sieveEnv {
	return &sieveEnv{spam: spam}
}

// GetEnvironment returns the value of a named environment item, and whether the
// item is supported at all. Names are case-insensitive (RFC 5183 section 4.1);
// go-sieve already lowercases before calling, but this does not rely on that.
//
// Items we cannot answer honestly report unsupported rather than "". mail-session
// runs privilege-dropped, after the SMTP conversation has ended, and never saw
// the client -- so remote-host, remote-ip and domain are unknown here, and
// claiming they are empty would be a different assertion from admitting we do
// not have them.
func (e *sieveEnv) GetEnvironment(name string) (string, bool) {
	switch strings.ToLower(name) {
	case "name":
		return envName, true
	case "version":
		return buildVersion()
	case "location":
		return envLocation, true
	case "phase":
		return envPhase, true
	case "host":
		host, err := os.Hostname()
		if err != nil || host == "" {
			return "", false
		}
		return host, true

	case "vnd.maildancer.spam-flag":
		if e.spam == nil {
			return "", false
		}
		if e.spam.IsSpam {
			return "YES", true
		}
		return "NO", true

	case "vnd.maildancer.spam-value":
		// The one threshold rules should use. A decimal score cannot be
		// compared in Sieve at all -- i;ascii-numeric (RFC 4790) is defined over
		// non-negative integers, so it reads "12.80" as 12 and a negative score
		// has no defined ordering.
		//
		// Absent from the header set means unsupported, never "0": 0 is a
		// meaningful point on the RFC 5235 scale ("message was not tested"), so
		// substituting it would assert something untrue.
		if e.spam == nil {
			return "", false
		}
		v, ok := e.spam.Headers[spamValueHeader]
		if !ok || v == "" {
			return "", false
		}
		return v, true

	case "vnd.maildancer.spam-score":
		// The checker's raw score, for :matches tests and for humans. Not
		// numerically comparable in Sieve -- see spam-value above.
		if e.spam == nil {
			return "", false
		}
		return fmt.Sprintf("%.2f", e.spam.Score), true
	}

	return "", false
}

// buildVersion reports the module version recorded at build time. A binary built
// without module information (or from an unstamped tree) has nothing truthful to
// report, so the item is unsupported rather than guessed.
func buildVersion() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "", false
	}
	return info.Main.Version, true
}
