// Package imap implements the IMAP4rev1 protocol (RFC 3501).
package imap

// Standard IMAP flags as defined in RFC 3501.
const (
	FlagSeen     = `\Seen`
	FlagAnswered = `\Answered`
	FlagFlagged  = `\Flagged`
	FlagDeleted  = `\Deleted`
	FlagDraft    = `\Draft`
	FlagRecent   = `\Recent`
)

// PermanentFlags are the flags that the server allows clients to set permanently.
// \Recent is server-managed and not included.
var PermanentFlags = []string{FlagSeen, FlagAnswered, FlagFlagged, FlagDeleted, FlagDraft}

// SystemFlags includes all standard flags including \Recent.
var SystemFlags = []string{FlagSeen, FlagAnswered, FlagFlagged, FlagDeleted, FlagDraft, FlagRecent}

// HasFlag returns true if the flag list contains the specified flag (case-insensitive).
func HasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if equalFold(f, flag) {
			return true
		}
	}
	return false
}

// AddFlag adds a flag to the list if not already present.
// Returns the updated list.
func AddFlag(flags []string, flag string) []string {
	if HasFlag(flags, flag) {
		return flags
	}
	return append(flags, flag)
}

// RemoveFlag removes a flag from the list.
// Returns the updated list.
func RemoveFlag(flags []string, flag string) []string {
	result := make([]string, 0, len(flags))
	for _, f := range flags {
		if !equalFold(f, flag) {
			result = append(result, f)
		}
	}
	return result
}

// equalFold is a simple case-insensitive string comparison.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
