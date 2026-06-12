package smtp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
	"github.com/infodancer/maildancer/internal/mail-remote/mx"
)

// maxMXAttempts caps connection attempts per delivery run. The MX list is
// attacker-controlled data; a hostile domain could otherwise publish dozens
// of records and turn one delivery into a port scan on its behalf.
const maxMXAttempts = 5

// DeliverViaMX resolves MX hosts for the recipient domain and delivers
// each envelope via direct SMTP. Hosts are tried in priority order, both
// for the initial connection and on mid-session connection failures:
// envelopes whose outcome was never determined fail over to the next host.
// Envelopes with a definitive outcome never move -- an SMTP verdict (4xx/5xx)
// stands, and an envelope whose DATA terminator was sent but whose final
// response was lost is deferred to the queue retry rather than re-sent
// (duplicate-delivery risk; see AmbiguousError).
//
// Each envelope is a separate MAIL FROM transaction (VERP).
// No SMTP AUTH is used (standard for MX delivery).
//
// Returns a map of envelope path → error, like DeliverViaSmarthost.
func DeliverViaMX(_ context.Context, resolver mx.Resolver, hostname, domain, bodyPath string, envs []*envelope.Envelope, maxTxn int) map[string]error {
	results := make(map[string]error, len(envs))

	hosts, err := mx.Lookup(resolver, domain)
	if err != nil {
		classifiedErr := classifyMXError(err)
		for _, env := range envs {
			results[env.Path] = classifiedErr
		}
		return results
	}

	bodySize, err := fileSize(bodyPath)
	if err != nil {
		for _, env := range envs {
			results[env.Path] = fmt.Errorf("stat body %s: %w", bodyPath, err)
		}
		return results
	}

	pending := envs
	attempts := 0
	var lastErr error
	for _, h := range hosts {
		if len(pending) == 0 || attempts >= maxMXAttempts {
			break
		}
		attempts++

		slog.Debug("trying MX host", "host", h.Name, "addr", h.Addr())
		c, err := DialMX(h.Addr(), hostname)
		if err != nil {
			slog.Debug("MX host failed", "host", h.Name, "error", err)
			lastErr = err
			continue
		}

		// SIZE limits differ per host; a too-large verdict from one host
		// only rules out that host.
		if err := checkSize(c, bodySize); err != nil {
			slog.Debug("MX host rejected size", "host", h.Name, "error", err)
			lastErr = err
			_ = c.Close()
			continue
		}

		slog.Info("connected to MX host", "host", h.Name)
		retryable, cause := deliverAll(c, bodyPath, pending, results, maxTxn)
		_ = c.Close()
		if len(retryable) == 0 {
			pending = nil
			break
		}
		slog.Info("connection to MX host lost mid-session; failing over",
			"host", h.Name, "remaining", len(retryable), "error", cause)
		pending = retryable
		lastErr = cause
	}

	if len(pending) > 0 {
		if lastErr == nil {
			lastErr = errors.New("no MX hosts to try")
		}
		finalErr := fmt.Errorf("all usable MX hosts failed for %s: %w", domain, lastErr)
		for _, env := range pending {
			results[env.Path] = finalErr
		}
	}
	return results
}

// classifyMXError converts mx.PermanentError into smtp.PermanentError
// so the caller's error handling works uniformly.
func classifyMXError(err error) error {
	var pe *mx.PermanentError
	if errors.As(err, &pe) {
		return &PermanentError{Err: err}
	}
	return err
}
