// Package liblog classifies the log level of messages emitted by the go-imap and
// go-smtp libraries, which route both genuine faults and benign client-caused
// events through a single levelless Printf/Println sink (see issue #140). It is
// the policy passed to logging.NewStdLoggerFunc by imapd and smtpd.
package liblog

import (
	"log/slog"
	"strings"
)

// benignPrefixes are message prefixes go-imap/go-smtp use for client-caused,
// non-actionable events -- malformed input, disconnects, and TLS-negotiation
// failures from the scanners and probes that constantly hit public mail ports.
// These are demoted below error so genuine faults (panics, internal-error
// responses, listener accept errors) are not buried.
//
// The kept-at-error messages are deliberately NOT matched here: go-imap's
// "handling <CMD> command: <err>" (the SERVERBUG cause -- the whole point of
// #131), "panic ..." from either library, go-imap's "failed to create session",
// and go-smtp's "accept error". Note "error handling " (go-smtp, benign) and
// "handling " (go-imap, a fault) are distinct prefixes.
var benignPrefixes = []string{
	"failed to read command",   // go-imap: malformed command line or client EOF
	"failed to write greeting", // go-imap: client disconnected/probed before greeting
	"failed to close session",  // go-imap: benign teardown error
	"error handling ",          // go-smtp: per-connection client/connection error
}

// Level classifies a go-imap/go-smtp library log message: benign client-caused
// events at info, everything else at error.
func Level(msg string) slog.Level {
	for _, p := range benignPrefixes {
		if strings.HasPrefix(msg, p) {
			return slog.LevelInfo
		}
	}
	return slog.LevelError
}
