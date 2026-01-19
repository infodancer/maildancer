package smtp

import (
	"context"
	"crypto/tls"
	"regexp"
)

// starttlsPattern matches the STARTTLS command
var starttlsPattern = regexp.MustCompile(`(?i)^STARTTLS\s*$`)

// STARTTLSCommand implements the STARTTLS command (RFC 3207)
type STARTTLSCommand struct {
	tlsConfig *tls.Config
}

func (c *STARTTLSCommand) Pattern() *regexp.Regexp {
	return starttlsPattern
}

func (c *STARTTLSCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	// Check if TLS is already active
	if session.IsTLSActive() {
		return SMTPResult{
			Code:    503,
			Message: "5.5.1 TLS already active",
		}, nil
	}

	// Check if TLS configuration is available
	if c.tlsConfig == nil {
		return SMTPResult{
			Code:    454,
			Message: "4.7.0 TLS not available",
		}, nil
	}

	// Return 220 to signal readiness for TLS upgrade
	// The actual upgrade is performed by the handler after sending this response
	return SMTPResult{
		Code:    220,
		Message: "2.0.0 Ready to start TLS",
	}, nil
}

// TLSConfig returns the TLS configuration for the upgrade
func (c *STARTTLSCommand) TLSConfig() *tls.Config {
	return c.tlsConfig
}
