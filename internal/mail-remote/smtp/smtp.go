// Package smtp implements SMTP delivery for mail-remote.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// SMTPCode extracts the SMTP reply code from an error chain.
// Returns 0 if no SMTP error is found (e.g., connection failures).
func SMTPCode(err error) int {
	var smtpErr *gosmtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code
	}
	return 0
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

// isConnectionError reports whether err indicates the underlying TCP
// connection is dead (I/O error, reset, timeout) rather than a protocol-
// level rejection. A dead connection cannot be reused for further envelopes.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var smtpErr *gosmtp.SMTPError
	if errors.As(err, &smtpErr) {
		return false // protocol-level rejection; connection is still alive
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

// Smarthost holds configuration for relaying via a fixed SMTP smarthost.
type Smarthost struct {
	// Addr is the smarthost address in host:port form (e.g. "smtp.relay.com:587").
	Addr string
	// Username is the SMTP AUTH username. Empty disables AUTH.
	Username string
	// Password is the SMTP AUTH password. Prefer passing via --outbound-fd;
	// falls back to MAIL_REMOTE_PASSWORD env var.
	Password string
}

// SmarthostFromEnv builds a Smarthost using the MAIL_REMOTE_PASSWORD environment variable.
// Deprecated: prefer --outbound-fd for secure credential passing.
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
// maxTxn limits the number of MAIL FROM transactions per connection.
// Envelopes beyond the limit receive a temporary error for retry on the next scan.
//
// Returns a map of envelope path → error. A nil error means success. The
// caller should delete the envelope file on success and update its mtime on
// temporary failure.
func DeliverViaSmarthost(_ context.Context, sh Smarthost, bodyPath string, envs []*envelope.Envelope, maxTxn int) map[string]error {
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

// deliverAll sends each envelope over the connection, resetting between
// transactions and aborting early if the connection dies or the transaction
// limit is reached. maxTxn <= 0 means no limit.
func deliverAll(c *gosmtp.Client, bodyPath string, envs []*envelope.Envelope, results map[string]error, maxTxn int) {
	for i, env := range envs {
		if maxTxn > 0 && i >= maxTxn {
			limitErr := fmt.Errorf("transaction limit (%d) reached; deferring", maxTxn)
			for _, remaining := range envs[i:] {
				results[remaining.Path] = limitErr
			}
			return
		}

		err := deliver(c, bodyPath, env)
		results[env.Path] = err

		if err != nil && isConnectionError(err) {
			connErr := fmt.Errorf("connection lost: %w", err)
			for _, remaining := range envs[i+1:] {
				results[remaining.Path] = connErr
			}
			return
		}

		// RSET between transactions to clean up server state. Skip after
		// the last envelope (we'll QUIT instead). We RSET after both
		// success and protocol errors (e.g. 550) to ensure the next
		// MAIL FROM starts clean. Connection errors are handled above.
		if i < len(envs)-1 {
			if resetErr := c.Reset(); resetErr != nil {
				slog.Debug("RSET failed between transactions", "error", resetErr)
				if isConnectionError(resetErr) {
					connErr := fmt.Errorf("connection lost during RSET: %w", resetErr)
					for _, remaining := range envs[i+1:] {
						results[remaining.Path] = connErr
					}
					return
				}
			}
		}
	}
}

// deliver sends one envelope over an already-authenticated SMTP connection.
// Uses explicit MAIL/RCPT/DATA to capture the remote queue ID.
func deliver(c *gosmtp.Client, bodyPath string, env *envelope.Envelope) error {
	body, err := os.Open(bodyPath)
	if err != nil {
		return fmt.Errorf("open body %s: %w", bodyPath, err)
	}
	defer func() { _ = body.Close() }()

	if err := c.Mail(env.Sender, nil); err != nil {
		return classifyError(fmt.Errorf("MAIL FROM <%s>: %w", env.Sender, err))
	}

	if err := c.Rcpt(env.Recipient, nil); err != nil {
		return classifyError(fmt.Errorf("RCPT TO <%s>: %w", env.Recipient, err))
	}

	dataCmd, err := c.Data()
	if err != nil {
		return classifyError(fmt.Errorf("DATA: %w", err))
	}

	if _, err := io.Copy(dataCmd, body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	resp, err := dataCmd.CloseWithResponse()
	if err != nil {
		return classifyError(fmt.Errorf("DATA close: %w", err))
	}

	slog.Info("delivered", "recipient", env.Recipient, "remote_status", resp.StatusText)
	return nil
}

// fileSize returns the size of a file in bytes.
func fileSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// checkSize verifies the body fits within the server's advertised SIZE limit.
// Returns a PermanentError if the message is too large.
func checkSize(c *gosmtp.Client, bodyBytes int64) error {
	maxSize, ok := c.MaxMessageSize()
	if !ok || maxSize == 0 {
		return nil
	}
	if bodyBytes > int64(maxSize) {
		return &PermanentError{
			Err: fmt.Errorf("message size %d exceeds server limit %d", bodyBytes, maxSize),
		}
	}
	return nil
}
