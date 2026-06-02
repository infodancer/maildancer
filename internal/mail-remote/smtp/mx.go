package smtp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
	"github.com/infodancer/maildancer/internal/mail-remote/mx"
)

// DeliverViaMX resolves MX hosts for the recipient domain and delivers
// each envelope via direct SMTP. MX hosts are tried in priority order;
// the first one that accepts a TCP connection is used for all envelopes.
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

	c, err := connectToMX(hosts, hostname)
	if err != nil {
		for _, env := range envs {
			results[env.Path] = fmt.Errorf("all MX hosts unreachable for %s: %w", domain, err)
		}
		return results
	}
	defer func() { _ = c.Close() }()

	bodySize, err := fileSize(bodyPath)
	if err != nil {
		for _, env := range envs {
			results[env.Path] = fmt.Errorf("stat body %s: %w", bodyPath, err)
		}
		return results
	}

	if err := checkSize(c, bodySize); err != nil {
		for _, env := range envs {
			results[env.Path] = err
		}
		return results
	}

	deliverAll(c, bodyPath, envs, results, maxTxn)
	return results
}

// connectToMX tries each MX host in order and returns the first successful
// SMTP connection. Returns the last error if all hosts fail.
func connectToMX(hosts []mx.Host, hostname string) (*gosmtp.Client, error) {
	var lastErr error
	for _, h := range hosts {
		slog.Debug("trying MX host", "host", h.Name, "addr", h.Addr())
		c, err := DialMX(h.Addr(), hostname)
		if err != nil {
			slog.Debug("MX host failed", "host", h.Name, "error", err)
			lastErr = err
			continue
		}
		slog.Info("connected to MX host", "host", h.Name)
		return c, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no MX hosts to try")
	}
	return nil, lastErr
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
