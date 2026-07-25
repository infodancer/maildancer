// Package peersignal names the abuse signals the protocol daemons report about
// a peer and session-manager sets thresholds for (#206, rule 3).
//
// It exists so the producer and the policy share one definition. The names
// travel over the wire in ReportPeerRequest.signal and appear verbatim as keys
// in the `[session-manager.peerfilter.abuse_thresholds]` config table, so they
// are a compatibility surface: renaming one silently orphans an operator's
// configured threshold. Add new names, do not repurpose old ones.
//
// The package deliberately has no dependencies. A daemon must be able to name a
// signal without importing session-manager's policy, and session-manager must be
// able to threshold one without importing a daemon.
package peersignal

// Signals a protocol handler observes and reports itself.
const (
	// RelayDenied is an unauthenticated client asking the server to relay to a
	// domain it does not host -- an open-relay probe. Nothing legitimate does
	// this: a real MTA delivering to us names one of our own domains, and a
	// real submission client authenticates first.
	RelayDenied = "relay_denied"

	// EarlyTalker is a client that sent data before the greeting. Reserved;
	// detecting it needs a hook the SMTP library does not currently expose.
	EarlyTalker = "early_talker"

	// MalformedCommand is a syntactically invalid protocol command. Reserved;
	// go-smtp handles command parsing internally and does not surface these.
	MalformedCommand = "malformed_command"

	// DataAbort is a transaction dropped mid-DATA. Reserved.
	DataAbort = "data_abort"
)

// Signals session-manager derives from RPCs it already serves, with no report
// from the daemon needed.
const (
	// InvalidRecipient is a RCPT TO naming a nonexistent user on a domain the
	// server does host -- the recipient dictionary attack. Recorded from
	// ValidateRecipient, which already knows whether the user exists.
	//
	// Unlike an authentication attempt against a nonexistent account, this is
	// not a first-attempt ban: legitimate senders do write to addresses that
	// have been retired, and a real MTA retries. It is a counted rate.
	InvalidRecipient = "invalid_recipient"
)
