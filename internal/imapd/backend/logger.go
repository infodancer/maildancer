package backend

import (
	"fmt"
	"log/slog"
)

// imapLogger adapts a *slog.Logger to go-imap's imapserver.Logger interface (a
// Printf-style sink). go-imap routes internal faults through this logger:
// panics, session/greeting failures, and -- most importantly -- the
// "handling <CMD> command: <err>" messages it emits immediately before
// replacing the response with "NO [SERVERBUG] Internal server error".
//
// Without this adapter, imapserver.Options.Logger is nil and go-imap falls back
// to log.Default(), so those underlying errors land on stderr unstructured and
// levelless -- invisible in our structured logs and impossible to alert on.
// Wiring this in ensures every SERVERBUG carries a matching error-level record.
// See issue #131.
type imapLogger struct {
	logger *slog.Logger
}

// Printf implements imapserver.Logger. go-imap only logs faults through this
// interface, so emitting at error level is correct.
func (l imapLogger) Printf(format string, args ...any) {
	l.logger.Error(fmt.Sprintf(format, args...), "component", "imapserver")
}
