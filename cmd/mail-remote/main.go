// Command mail-remote is the remote delivery agent for the infodancer mail stack.
// It is invoked by queue-manager (or by hand) to deliver one or more envelopes
// sharing the same recipient domain.
//
// Usage:
//
//	mail-remote [flags] <body-file> <envelope-file> [envelope-file ...]
//
// Flags:
//
//	--smarthost host:port  Relay all mail via this SMTP smarthost (STARTTLS).
//	--smarthost-user user  SMTP AUTH username. Password from MAIL_REMOTE_PASSWORD env var.
//
// Exit codes:
//
//	0:  All envelopes delivered successfully.
//	1:  Fatal error (bad arguments, unreadable files, etc.).
//	75: One or more envelopes failed with a temporary error (EX_TEMPFAIL; retry later).
//	69: One or more envelopes failed with a permanent error (EX_UNAVAILABLE; no retry).
//
// Without --smarthost, mail-remote performs DNS-based delivery (SRV → new-protocol;
// MX → SMTP; A → SMTP). DNS delivery is not yet implemented.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
	"github.com/infodancer/maildancer/internal/mail-remote/smtp"
)

// Exit codes follow sysexits.h conventions used by qmail and Postfix.
const (
	exOK          = 0
	exUsage       = 1
	exUnavailable = 69 // EX_UNAVAILABLE: permanent failure
	exTempFail    = 75 // EX_TEMPFAIL: temporary failure, retry later
)

func main() {
	os.Exit(run())
}

func run() int {
	smarthostAddr := flag.String("smarthost", "", "SMTP smarthost address (host:port)")
	smarthostUser := flag.String("smarthost-user", "", "SMTP AUTH username for smarthost")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mail-remote [flags] <body-file> <envelope-file> [envelope-file ...]")
		return exUsage
	}

	bodyPath := args[0]
	envPaths := args[1:]

	if _, err := os.Stat(bodyPath); err != nil {
		slog.Error("body file not accessible", "path", bodyPath, "error", err)
		return exUsage
	}

	envs := make([]*envelope.Envelope, 0, len(envPaths))
	for _, p := range envPaths {
		env, err := envelope.Parse(p)
		if err != nil {
			slog.Error("failed to parse envelope", "path", p, "error", err)
			return exUsage
		}
		envs = append(envs, env)
	}

	if *smarthostAddr == "" {
		fmt.Fprintln(os.Stderr, "error: DNS-based delivery not yet implemented; --smarthost is required")
		return exUsage
	}

	sh := smtp.SmarthostFromEnv(*smarthostAddr, *smarthostUser)
	results := smtp.DeliverViaSmarthost(context.Background(), sh, bodyPath, envs)

	tempFail, permFail := false, false
	for path, err := range results {
		if err == nil {
			slog.Info("delivered", "envelope", path)
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("could not remove delivered envelope", "path", path, "error", removeErr)
			}
			continue
		}

		if smtp.IsPermanent(err) {
			slog.Error("permanent delivery failure", "envelope", path, "error", err)
			permFail = true
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("could not remove rejected envelope", "path", path, "error", removeErr)
			}
		} else {
			slog.Error("temporary delivery failure", "envelope", path, "error", err)
			tempFail = true
			// Touch mtime to update the backoff clock.
			now := time.Now()
			if touchErr := os.Chtimes(path, now, now); touchErr != nil {
				slog.Warn("could not update envelope mtime", "path", path, "error", touchErr)
			}
		}
	}

	switch {
	case permFail && !tempFail:
		return exUnavailable
	case tempFail:
		return exTempFail
	default:
		return exOK
	}
}
