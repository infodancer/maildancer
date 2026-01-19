package pop3

import (
	"context"
	"fmt"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
)

// AuthProvider is the interface for authentication operations.
type AuthProvider interface {
	Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error)
}

// capaCommand implements the CAPA command (RFC 2449).
type capaCommand struct{}

func (c *capaCommand) Name() string {
	return "CAPA"
}

func (c *capaCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// CAPA takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "CAPA command takes no arguments"}, nil
	}

	caps := sess.Capabilities()

	return Response{
		OK:      true,
		Message: "Capability list follows",
		Lines:   caps,
	}, nil
}

// stlsCommand implements the STLS command (RFC 2595).
type stlsCommand struct{}

func (s *stlsCommand) Name() string {
	return "STLS"
}

func (s *stlsCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// STLS takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "STLS command takes no arguments"}, nil
	}

	// STLS is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Check if STLS is available
	if !sess.CanSTLS() {
		if sess.IsTLSActive() {
			return Response{OK: false, Message: "Already using TLS"}, nil
		}
		return Response{OK: false, Message: "TLS not available"}, nil
	}

	// Return success - the handler will perform the TLS upgrade
	return Response{OK: true, Message: "Begin TLS negotiation"}, nil
}

// userCommand implements the USER command (RFC 1939).
type userCommand struct{}

func (u *userCommand) Name() string {
	return "USER"
}

func (u *userCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// USER is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Require TLS for USER command
	if !sess.IsTLSActive() {
		return Response{OK: false, Message: "TLS required for authentication"}, nil
	}

	// USER requires exactly one argument
	if len(args) != 1 {
		return Response{OK: false, Message: "USER command requires username argument"}, nil
	}

	username := args[0]
	if username == "" {
		return Response{OK: false, Message: "Username cannot be empty"}, nil
	}

	// Store the username in the session
	sess.SetUsername(username)

	return Response{OK: true, Message: fmt.Sprintf("User %s accepted", username)}, nil
}

// passCommand implements the PASS command (RFC 1939).
type passCommand struct {
	authProvider AuthProvider
	msgStore     msgstore.MessageStore
}

func (p *passCommand) Name() string {
	return "PASS"
}

func (p *passCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// PASS is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Require TLS for PASS command
	if !sess.IsTLSActive() {
		return Response{OK: false, Message: "TLS required for authentication"}, nil
	}

	// USER must have been called first
	username := sess.Username()
	if username == "" {
		return Response{OK: false, Message: "No username specified"}, nil
	}

	// PASS requires exactly one argument
	if len(args) != 1 {
		return Response{OK: false, Message: "PASS command requires password argument"}, nil
	}

	password := args[0]

	// Authenticate using the auth provider
	authSession, err := p.authProvider.Authenticate(ctx, username, password)
	if err != nil {
		// Return generic error to prevent user enumeration
		conn.Logger().Info("authentication failed",
			"username", username,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Authentication failed"}, nil
	}

	// Authentication successful - transition to TRANSACTION state
	sess.SetAuthenticated(authSession)

	// Initialize mailbox if message store is available
	if p.msgStore != nil {
		if err := sess.InitializeMailbox(ctx, p.msgStore); err != nil {
			conn.Logger().Error("failed to initialize mailbox",
				"username", username,
				"mailbox", authSession.User.Mailbox,
				"error", err.Error(),
			)
			return Response{OK: false, Message: "Failed to access mailbox"}, nil
		}
	}

	conn.Logger().Info("authentication successful",
		"username", username,
		"mailbox", authSession.User.Mailbox,
	)

	return Response{OK: true, Message: fmt.Sprintf("Logged in as %s", username)}, nil
}

// quitCommand implements the QUIT command (RFC 1939).
type quitCommand struct{}

func (q *quitCommand) Name() string {
	return "QUIT"
}

func (q *quitCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// QUIT takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "QUIT command takes no arguments"}, nil
	}

	var message string

	switch sess.State() {
	case StateAuthorization:
		// Just say goodbye
		message = "Goodbye"

	case StateTransaction:
		// Enter UPDATE state to commit changes (future: commit deletions)
		sess.EnterUpdate()
		message = "Logging out"

	default:
		message = "Goodbye"
	}

	return Response{OK: true, Message: message}, nil
}

// RegisterAuthCommands registers all authentication-related commands.
func RegisterAuthCommands(authProvider AuthProvider, msgStore msgstore.MessageStore) {
	RegisterCommand(&capaCommand{})
	RegisterCommand(&stlsCommand{})
	RegisterCommand(&userCommand{})
	RegisterCommand(&passCommand{authProvider: authProvider, msgStore: msgStore})
	RegisterCommand(&quitCommand{})
}
