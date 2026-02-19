package imap

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/infodancer/maildancer/internal/imapd/server"
	"github.com/infodancer/maildancer/msgstore"
)

// starttlsCommand implements the STARTTLS command.
type starttlsCommand struct{}

func (c *starttlsCommand) Name() string { return "STARTTLS" }

func (c *starttlsCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.ListenerMode() != "imap" {
		return writeBAD(w, tag, "STARTTLS not available in this mode")
	}

	if conn.IsTLS() {
		return writeBAD(w, tag, "Already using TLS")
	}

	if !sess.IsTLSAvailable() {
		return writeNO(w, tag, "TLS not configured")
	}

	if err := writeOK(w, tag, "Begin TLS negotiation"); err != nil {
		return err
	}
	if err := flushConn(conn); err != nil {
		return err
	}

	// Perform TLS upgrade
	if err := conn.UpgradeToTLS(sess.TLSConfig()); err != nil {
		sess.Logger().Error("TLS upgrade failed", "error", err.Error())
		return err
	}

	sess.Collector().TLSConnectionEstablished()
	sess.Logger().Info("TLS upgrade successful")
	return nil
}

// authenticateCommand implements the AUTHENTICATE command.
type authenticateCommand struct {
	auth  DomainAuthenticator
	store msgstore.MessageStore
}

func (c *authenticateCommand) Name() string { return "AUTHENTICATE" }

func (c *authenticateCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateNotAuthenticated {
		return writeBAD(w, tag, "Already authenticated")
	}

	if !conn.IsTLS() {
		return writeNO(w, tag, "[PRIVACYREQUIRED] TLS required for authentication")
	}

	mechanism := strings.TrimSpace(strings.ToUpper(args))
	if mechanism != "PLAIN" {
		return writeNO(w, tag, "Unsupported authentication mechanism")
	}

	// Send continuation request
	if err := writeContinuation(w, ""); err != nil {
		return err
	}
	if err := flushConn(conn); err != nil {
		return err
	}

	// Read base64-encoded response
	line, err := conn.Reader().ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")

	// Check for cancellation
	if line == "*" {
		return writeBAD(w, tag, "Authentication cancelled")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return writeNO(w, tag, "Invalid base64 encoding")
	}

	// Parse SASL PLAIN: \0username\0password
	parts := strings.SplitN(string(decoded), "\x00", 3)
	if len(parts) != 3 {
		return writeNO(w, tag, "Invalid SASL PLAIN response")
	}

	username := parts[1]
	password := parts[2]

	if username == "" {
		return writeNO(w, tag, "Username cannot be empty")
	}

	// Authenticate
	result, err := c.auth.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		sess.Logger().Info("authentication failed", "username", username, "error", err.Error())
		sess.Collector().AuthAttempt(extractDomain(username), false)
		return writeNO(w, tag, "Authentication failed")
	}

	sess.SetAuthenticated(result.Session, username, result.Domain, c.store)
	sess.Collector().AuthAttempt(sess.UserDomain(), true)
	sess.Logger().Info("authentication successful", "username", username)

	return writeOK(w, tag, "AUTHENTICATE completed")
}

// loginCommand implements the LOGIN command.
type loginCommand struct {
	auth  DomainAuthenticator
	store msgstore.MessageStore
}

func (c *loginCommand) Name() string { return "LOGIN" }

func (c *loginCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateNotAuthenticated {
		return writeBAD(w, tag, "Already authenticated")
	}

	if !conn.IsTLS() {
		return writeNO(w, tag, "[PRIVACYREQUIRED] TLS required for authentication")
	}

	// Parse username and password
	username, rest := ParseQuotedOrAtom(args)
	password, _ := ParseQuotedOrAtom(rest)

	if username == "" || password == "" {
		return writeBAD(w, tag, "LOGIN requires username and password")
	}

	// Authenticate
	result, err := c.auth.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		sess.Logger().Info("login failed", "username", username, "error", err.Error())
		sess.Collector().AuthAttempt(extractDomain(username), false)
		return writeNO(w, tag, "Login failed")
	}

	sess.SetAuthenticated(result.Session, username, result.Domain, c.store)
	sess.Collector().AuthAttempt(sess.UserDomain(), true)
	sess.Logger().Info("login successful", "username", username)

	return writeOK(w, tag, "LOGIN completed")
}
