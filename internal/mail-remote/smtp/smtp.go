// Package smtp implements SMTP delivery for mail-remote.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
)

// PermanentError wraps an error that indicates a permanent delivery failure
// (SMTP 5xx). The envelope should be deleted; retrying will not help.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// IsPermanent reports whether err indicates a permanent delivery failure.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// classifyError wraps SMTP 5xx errors as PermanentError. All other errors
// (4xx, dial failures, I/O errors) are returned unchanged (temporary).
func classifyError(err error) error {
	if err == nil {
		return nil
	}
	var smtpErr *gosmtp.SMTPError
	if errors.As(err, &smtpErr) && smtpErr.Code >= 500 {
		return &PermanentError{Err: err}
	}
	return err
}

// Smarthost holds configuration for relaying via a fixed SMTP smarthost.
type Smarthost struct {
	// Addr is the smarthost address in host:port form (e.g. "smtp.relay.com:587").
	Addr string
	// Username is the SMTP AUTH username. Empty disables AUTH.
	Username string
	// Password is the SMTP AUTH password. Typically from MAIL_REMOTE_PASSWORD env var.
	Password string
}

// SmarthostFromEnv builds a Smarthost using the MAIL_REMOTE_PASSWORD environment variable.
func SmarthostFromEnv(addr, username string) Smarthost {
	return Smarthost{
		Addr:     addr,
		Username: username,
		Password: os.Getenv("MAIL_REMOTE_PASSWORD"),
	}
}

// dialFunc dials an SMTP server and returns a connected client.
// Overrideable in tests to substitute a plain (non-TLS) connection.
var dialFunc = func(addr string) (*gosmtp.Client, error) {
	return gosmtp.DialStartTLS(addr, nil)
}

// DeliverViaSmarthost opens one SMTP connection to the configured smarthost
// and delivers each envelope in turn. Each envelope is a separate MAIL FROM
// transaction (required because VERP produces a unique sender per recipient).
//
// Returns a map of envelope path → error. A nil error means success. The
// caller should delete the envelope file on success and update its mtime on
// temporary failure.
func DeliverViaSmarthost(_ context.Context, sh Smarthost, bodyPath string, envs []*envelope.Envelope) map[string]error {
	results := make(map[string]error, len(envs))

	c, err := dialFunc(sh.Addr)
	if err != nil {
		for _, env := range envs {
			results[env.Path] = fmt.Errorf("dial %s: %w", sh.Addr, err)
		}
		return results
	}
	defer func() { _ = c.Close() }()

	if sh.Username != "" {
		auth := sasl.NewPlainClient("", sh.Username, sh.Password)
		if err := c.Auth(auth); err != nil {
			for _, env := range envs {
				results[env.Path] = fmt.Errorf("smtp auth: %w", err)
			}
			return results
		}
	}

	for _, env := range envs {
		results[env.Path] = deliver(c, bodyPath, env)
	}
	return results
}

// deliver sends one envelope over an already-authenticated SMTP connection.
func deliver(c *gosmtp.Client, bodyPath string, env *envelope.Envelope) error {
	body, err := os.Open(bodyPath)
	if err != nil {
		return fmt.Errorf("open body %s: %w", bodyPath, err)
	}
	defer func() { _ = body.Close() }()

	if err := c.SendMail(env.Sender, []string{env.Recipient}, body); err != nil {
		return classifyError(fmt.Errorf("smtp send to %s: %w", env.Recipient, err))
	}
	return nil
}
