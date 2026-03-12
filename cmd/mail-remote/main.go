// Command mail-remote is the remote delivery agent for the infodancer mail stack.
// It is invoked by queue-manager (or by hand) to deliver one or more envelopes
// sharing the same recipient domain.
//
// Usage:
//
//	mail-remote [flags] <body-file> <envelope-file> [envelope-file ...]
//
// Protocol (when invoked by queue-manager):
//
//	stdin:  JSON outbound config {"strategy","smarthost","smarthost_user","password"}
//	stdout: JSON delivery results [{"envelope","status","smtp_code","diagnostic"},...]
//	stderr: structured logging (slog)
//
// When stdin is a terminal (manual invocation), no config is read from stdin.
// Use --smarthost and --smarthost-user flags instead, with MAIL_REMOTE_PASSWORD
// env var for the password.
//
// Flags (manual overrides — take precedence over stdin config):
//
//	--config path         Path to shared TOML config file (reads [mail-remote] section).
//	--smarthost host:port Relay via SMTP smarthost (overrides stdin config).
//	--smarthost-user user SMTP AUTH username (overrides stdin config).
//	--hostname fqdn       EHLO hostname for direct MX delivery (required without smarthost).
//	--final               Signal that this is the final delivery attempt (try all transports).
//
// Exit codes:
//
//	0:  All envelopes delivered successfully.
//	1:  Fatal error (bad arguments, unreadable files, etc.).
//	75: One or more envelopes failed with a temporary error (EX_TEMPFAIL; retry later).
//	69: One or more envelopes failed with a permanent error (EX_UNAVAILABLE; no retry).
//
// Without a smarthost, mail-remote performs DNS-based delivery (MX → SMTP;
// A/AAAA → SMTP). Future: SRV → new-protocol (SDMP).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/mail-remote/config"
	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
	"github.com/infodancer/maildancer/internal/mail-remote/mx"
	"github.com/infodancer/maildancer/internal/mail-remote/smtp"
)

// recipientResult is the per-recipient delivery outcome written to stdout
// as a JSON array. queue-manager reads this via pipe for delivery logging
// and DSN generation.
type recipientResult struct {
	Envelope   string `json:"envelope"`
	Status     string `json:"status"`     // "delivered", "perm_fail", "temp_fail"
	SMTPCode   int    `json:"smtp_code"`  // SMTP reply code; 0 if no SMTP response
	Diagnostic string `json:"diagnostic"` // SMTP reply text or error string
}

// outboundConfig is the JSON structure read from stdin when invoked by
// queue-manager. It carries all smarthost settings including the password,
// avoiding environment variables (visible in /proc/pid/environ).
type outboundConfig struct {
	Strategy  string `json:"strategy"`  // "direct" | "smarthost"
	Smarthost string `json:"smarthost"` // host:port
	Username  string `json:"smarthost_user"`
	Password  string `json:"password"`
}

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

// readStdinConfig reads JSON outbound config from stdin if it's a pipe.
// Returns nil if stdin is a terminal or empty.
func readStdinConfig() *outboundConfig {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	// Only read if stdin is a pipe (not a terminal).
	if fi.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg outboundConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("failed to parse outbound config from stdin", "error", err)
		return nil
	}
	return &cfg
}

func run() int {
	configPath := flag.String("config", "", "path to shared TOML config file")
	smarthostAddr := flag.String("smarthost", "", "SMTP smarthost address (host:port)")
	smarthostUser := flag.String("smarthost-user", "", "SMTP AUTH username for smarthost")
	hostname := flag.String("hostname", "", "EHLO hostname for direct MX delivery")
	final := flag.Bool("final", false, "final delivery attempt (try all transports)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mail-remote [flags] <body-file> <envelope-file> [envelope-file ...]")
		return exUsage
	}

	// Load config: TOML defaults → env overrides → CLI flag overrides.
	cfg := config.Default()
	if *configPath != "" {
		var err error
		cfg, err = config.Load(*configPath)
		if err != nil {
			slog.Error("failed to load config", "path", *configPath, "error", err)
			return exUsage
		}
	}
	cfg = config.ApplyEnv(cfg)

	// Read outbound config from stdin (pipe from queue-manager).
	stdinCfg := readStdinConfig()

	// Apply stdin config as baseline, then let CLI flags override.
	password := ""
	if stdinCfg != nil {
		if stdinCfg.Smarthost != "" {
			cfg.Smarthost.Addr = stdinCfg.Smarthost
		}
		if stdinCfg.Username != "" {
			cfg.Smarthost.User = stdinCfg.Username
		}
		password = stdinCfg.Password
	}

	// CLI flags override stdin config.
	if *smarthostAddr != "" {
		cfg.Smarthost.Addr = *smarthostAddr
	}
	if *smarthostUser != "" {
		cfg.Smarthost.User = *smarthostUser
	}
	if *hostname != "" {
		cfg.Hostname = *hostname
	}

	// Env var password as fallback for manual invocation.
	if password == "" {
		password = os.Getenv("MAIL_REMOTE_PASSWORD")
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

	if *final {
		slog.Info("final delivery attempt", "envelopes", len(envs))
	}

	var results map[string]error
	if cfg.Smarthost.Addr != "" {
		sh := smtp.Smarthost{
			Addr:     cfg.Smarthost.Addr,
			Username: cfg.Smarthost.User,
			Password: password,
		}
		results = smtp.DeliverViaSmarthost(context.Background(), sh, bodyPath, envs, cfg.Smarthost.MaxTransactionsPerConn)
	} else {
		if cfg.Hostname == "" {
			fmt.Fprintln(os.Stderr, "error: --hostname (or config hostname) is required for direct MX delivery")
			return exUsage
		}
		domain, err := envs[0].RecipientDomain()
		if err != nil {
			slog.Error("cannot determine recipient domain", "error", err)
			return exUsage
		}
		results = smtp.DeliverViaMX(context.Background(), mx.NetResolver{}, cfg.Hostname, domain, bodyPath, envs, cfg.RemoteMX.MaxTransactionsPerConn)
	}

	tempFail, permFail := false, false
	var output []recipientResult
	for path, err := range results {
		if err == nil {
			slog.Info("delivered", "envelope", path)
			output = append(output, recipientResult{
				Envelope: path, Status: "delivered", SMTPCode: 250,
			})
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("could not remove delivered envelope", "path", path, "error", removeErr)
			}
			continue
		}

		if smtp.IsPermanent(err) {
			slog.Error("permanent delivery failure", "envelope", path, "error", err)
			permFail = true
			output = append(output, recipientResult{
				Envelope: path, Status: "perm_fail",
				SMTPCode: smtp.SMTPCode(err), Diagnostic: err.Error(),
			})
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("could not remove rejected envelope", "path", path, "error", removeErr)
			}
		} else {
			slog.Error("temporary delivery failure", "envelope", path, "error", err)
			tempFail = true
			output = append(output, recipientResult{
				Envelope: path, Status: "temp_fail",
				SMTPCode: smtp.SMTPCode(err), Diagnostic: err.Error(),
			})
			// Touch mtime to update the backoff clock.
			now := time.Now()
			if touchErr := os.Chtimes(path, now, now); touchErr != nil {
				slog.Warn("could not update envelope mtime", "path", path, "error", touchErr)
			}
		}
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		slog.Warn("could not write results to stdout", "error", err)
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
