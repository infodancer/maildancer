package smtp

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// authPattern matches AUTH commands: AUTH PLAIN [initial-response]
var authPattern = regexp.MustCompile(`(?i)^AUTH\s+(\w+)(?:\s+(.+))?$`)

// AUTHCommand implements the AUTH command for SMTP authentication
type AUTHCommand struct {
	authAgent interface{} // auth.AuthenticationAgent
}

func (c *AUTHCommand) Pattern() *regexp.Regexp {
	return authPattern
}

func (c *AUTHCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	mechanism := strings.ToUpper(matches[1])
	initialResponse := ""
	if len(matches) > 2 {
		initialResponse = matches[2]
	}

	// Security check 1: Already authenticated?
	if session.IsAuthenticated() {
		return SMTPResult{
			Code:    503,
			Message: "5.5.1 Bad sequence of commands",
		}, nil
	}

	// Security check 2: Must have greeted first
	if session.State() < StateGreeted {
		return SMTPResult{
			Code:    503,
			Message: "5.5.1 Bad sequence of commands",
		}, nil
	}

	// Security check 3: PLAIN/LOGIN require TLS (except localhost)
	if (mechanism == "PLAIN" || mechanism == "LOGIN") && !session.IsTLSActive() {
		clientIP := session.ConnInfo().ClientIP
		if !isLocalhost(clientIP) {
			return SMTPResult{
				Code:    538,
				Message: "5.7.11 Encryption required for requested authentication mechanism",
			}, nil
		}
	}

	// Dispatch to mechanism handler
	switch mechanism {
	case "PLAIN":
		return c.handlePlain(ctx, session, initialResponse)
	case "LOGIN":
		// LOGIN requires multi-turn support - not implemented yet
		return SMTPResult{
			Code:    504,
			Message: "5.5.4 Unrecognized authentication type",
		}, nil
	default:
		return SMTPResult{
			Code:    504,
			Message: "5.5.4 Unrecognized authentication type",
		}, nil
	}
}

// handlePlain implements AUTH PLAIN mechanism (RFC 4616)
// Format: \0username\0password (base64 encoded)
func (c *AUTHCommand) handlePlain(ctx context.Context, session *SMTPSession, initialResponse string) (SMTPResult, error) {
	if initialResponse == "" {
		// Client didn't provide initial response - not supported yet
		// Would need to send 334 and read continuation, which requires
		// handler support for multi-turn commands
		return SMTPResult{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}, nil
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(initialResponse)
	if err != nil {
		return SMTPResult{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}, nil
	}

	// Parse PLAIN format: \0username\0password
	// We also support the optional authorization identity: authzid\0username\0password
	parts := strings.Split(string(decoded), "\x00")

	var username, password string
	if len(parts) == 3 {
		// Format: authzid\0username\0password
		// We ignore authzid (authorization identity) for now
		username = parts[1]
		password = parts[2]
	} else if len(parts) == 2 {
		// Format: username\0password (missing authzid)
		username = parts[0]
		password = parts[1]
	} else {
		// Invalid format
		return SMTPResult{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}, nil
	}

	if username == "" || password == "" {
		return SMTPResult{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}, nil
	}

	// Cast authAgent to the correct type
	authAgent, ok := c.authAgent.(auth.AuthenticationAgent)
	if !ok || authAgent == nil {
		// Should not happen if command registry is configured correctly
		return SMTPResult{
			Code:    454,
			Message: "4.7.0 Temporary authentication failure",
		}, nil
	}

	// Attempt authentication
	authSession, err := authAgent.Authenticate(ctx, username, password)
	if err != nil {
		// Map errors to SMTP response codes
		// Both ErrAuthFailed and ErrUserNotFound return same code (no username enumeration)
		if err == autherrors.ErrAuthFailed || err == autherrors.ErrUserNotFound {
			return SMTPResult{
				Code:    535,
				Message: "5.7.8 Authentication credentials invalid",
			}, nil
		}

		// Other errors are temporary failures
		return SMTPResult{
			Code:    454,
			Message: "4.7.0 Temporary authentication failure",
		}, nil
	}

	// Authentication successful
	if authSession != nil && authSession.User != nil {
		session.SetAuthenticated(authSession.User.Username, "PLAIN")
	} else {
		session.SetAuthenticated(username, "PLAIN")
	}

	return SMTPResult{
		Code:    235,
		Message: "2.7.0 Authentication successful",
	}, nil
}
