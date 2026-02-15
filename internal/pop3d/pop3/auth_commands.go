package pop3

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-sasl"
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

// splitUsername splits "user@domain" into local part and domain.
// Returns the full username and empty domain if no @ is present.
func splitUsername(username string) (localPart, domainName string) {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[:idx], username[idx+1:]
	}
	return username, ""
}

// passCommand implements the PASS command (RFC 1939).
type passCommand struct {
	authProvider   AuthProvider
	msgStore       msgstore.MessageStore
	domainProvider DomainProvider
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

	// Split username into local part and domain
	localPart, domainName := splitUsername(username)

	// Try domain-specific authentication first
	if p.domainProvider != nil && domainName != "" {
		d := p.domainProvider.GetDomain(domainName)
		if d == nil {
			// Return generic error to prevent domain enumeration
			conn.Logger().Info("authentication failed: unknown domain",
				"username", username,
				"domain", domainName,
			)
			return Response{OK: false, Message: "Authentication failed"}, nil
		}

		// Authenticate with domain-specific auth agent using local part
		authSession, err := d.AuthAgent.Authenticate(ctx, localPart, password)
		if err != nil {
			conn.Logger().Info("domain authentication failed",
				"username", username,
				"domain", domainName,
				"error", err.Error(),
			)
			return Response{OK: false, Message: "Authentication failed"}, nil
		}

		sess.SetAuthenticated(authSession)

		// Initialize mailbox with domain-specific store
		if d.MessageStore != nil {
			if err := sess.InitializeMailbox(ctx, d.MessageStore); err != nil {
				conn.Logger().Error("failed to initialize domain mailbox",
					"username", username,
					"domain", domainName,
					"mailbox", authSession.User.Mailbox,
					"error", err.Error(),
				)
				return Response{OK: false, Message: "Failed to access mailbox"}, nil
			}
		}

		conn.Logger().Info("domain authentication successful",
			"username", username,
			"domain", domainName,
			"mailbox", authSession.User.Mailbox,
		)

		return Response{OK: true, Message: fmt.Sprintf("Logged in as %s", username)}, nil
	}

	// Fall back to global auth provider
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

// authCommand implements the AUTH command (RFC 5034).
type authCommand struct {
	authProvider   AuthProvider
	msgStore       msgstore.MessageStore
	domainProvider DomainProvider
}

func (a *authCommand) Name() string {
	return "AUTH"
}

func (a *authCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// AUTH is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Require TLS for AUTH command
	if !sess.IsTLSActive() {
		return Response{OK: false, Message: "TLS required for authentication"}, nil
	}

	// AUTH requires at least a mechanism argument
	if len(args) < 1 {
		return Response{OK: false, Message: "AUTH command requires mechanism argument"}, nil
	}

	mechanism := strings.ToUpper(args[0])

	// Check if mechanism is supported
	supported := false
	for _, mech := range SupportedSASLMechanisms() {
		if strings.EqualFold(mech, mechanism) {
			supported = true
			break
		}
	}
	if !supported {
		return Response{OK: false, Message: fmt.Sprintf("Unsupported mechanism: %s", mechanism)}, nil
	}

	// Create the SASL server based on mechanism
	var server sasl.Server
	switch mechanism {
	case sasl.Plain:
		server = sasl.NewPlainServer(func(identity, username, password string) error {
			// Split username into local part and domain
			localPart, domainName := splitUsername(username)

			// Try domain-specific authentication first
			if a.domainProvider != nil && domainName != "" {
				d := a.domainProvider.GetDomain(domainName)
				if d == nil {
					conn.Logger().Info("SASL authentication failed: unknown domain",
						"mechanism", mechanism,
						"username", username,
						"domain", domainName,
					)
					return fmt.Errorf("authentication failed")
				}

				// Authenticate with domain-specific auth agent using local part
				authSession, err := d.AuthAgent.Authenticate(ctx, localPart, password)
				if err != nil {
					conn.Logger().Info("SASL domain authentication failed",
						"mechanism", mechanism,
						"username", username,
						"domain", domainName,
						"error", err.Error(),
					)
					return err
				}

				sess.SetAuthenticated(authSession)
				sess.SetUsername(username)

				if d.MessageStore != nil {
					if err := sess.InitializeMailbox(ctx, d.MessageStore); err != nil {
						conn.Logger().Error("failed to initialize domain mailbox",
							"mechanism", mechanism,
							"username", username,
							"domain", domainName,
							"mailbox", authSession.User.Mailbox,
							"error", err.Error(),
						)
						return err
					}
				}

				conn.Logger().Info("SASL domain authentication successful",
					"mechanism", mechanism,
					"username", username,
					"domain", domainName,
					"mailbox", authSession.User.Mailbox,
				)
				return nil
			}

			// Fall back to global auth provider
			authSession, err := a.authProvider.Authenticate(ctx, username, password)
			if err != nil {
				conn.Logger().Info("SASL authentication failed",
					"mechanism", mechanism,
					"username", username,
					"error", err.Error(),
				)
				return err
			}

			// Authentication successful - transition to TRANSACTION state
			sess.SetAuthenticated(authSession)
			sess.SetUsername(username)

			// Initialize mailbox if message store is available
			if a.msgStore != nil {
				if err := sess.InitializeMailbox(ctx, a.msgStore); err != nil {
					conn.Logger().Error("failed to initialize mailbox",
						"username", username,
						"mailbox", authSession.User.Mailbox,
						"error", err.Error(),
					)
					return err
				}
			}

			conn.Logger().Info("SASL authentication successful",
				"mechanism", mechanism,
				"username", username,
				"mailbox", authSession.User.Mailbox,
			)
			return nil
		})
	default:
		return Response{OK: false, Message: fmt.Sprintf("Unsupported mechanism: %s", mechanism)}, nil
	}

	// Store the SASL server in the session
	sess.SetSASLServer(mechanism, server)

	// Check if there's an initial response (RFC 4954)
	var initialResponse []byte
	if len(args) > 1 {
		// Handle special case of "=" meaning empty initial response
		if args[1] == "=" {
			initialResponse = []byte{}
		} else {
			var err error
			initialResponse, err = DecodeSASLResponse(args[1])
			if err != nil {
				sess.ClearSASL()
				return Response{OK: false, Message: "Invalid base64 encoding"}, nil
			}
		}

		// Process the initial response
		return a.processSASLStep(ctx, sess, conn, initialResponse)
	}

	// No initial response - send empty challenge to request credentials
	return Response{Continuation: true, Challenge: ""}, nil
}

// processSASLStep processes a SASL response and returns the next challenge or completion.
func (a *authCommand) processSASLStep(ctx context.Context, sess *Session, conn ConnectionLogger, response []byte) (Response, error) {
	server := sess.SASLServer()
	if server == nil {
		return Response{OK: false, Message: "No SASL exchange in progress"}, nil
	}

	// Process the response
	challenge, done, err := server.Next(response)
	if err != nil {
		sess.ClearSASL()
		return Response{OK: false, Message: "Authentication failed"}, nil
	}

	if done {
		// Authentication complete
		sess.ClearSASL()
		return Response{OK: true, Message: fmt.Sprintf("Logged in as %s", sess.Username())}, nil
	}

	// Need more data - send challenge
	return Response{Continuation: true, Challenge: EncodeSASLChallenge(challenge)}, nil
}

// ProcessSASLResponse processes a SASL response from the handler.
// This is called when the handler receives a line during an active SASL exchange.
func (a *authCommand) ProcessSASLResponse(ctx context.Context, sess *Session, conn ConnectionLogger, line string) (Response, error) {
	// Check for cancellation
	if line == "*" {
		sess.ClearSASL()
		return Response{OK: false, Message: "Authentication cancelled"}, nil
	}

	// Decode the response
	response, err := DecodeSASLResponse(line)
	if err != nil {
		sess.ClearSASL()
		return Response{OK: false, Message: "Invalid base64 encoding"}, nil
	}

	return a.processSASLStep(ctx, sess, conn, response)
}

// RegisterAuthCommands registers all authentication-related commands.
// domainProvider may be nil when domain-aware auth is not configured.
func RegisterAuthCommands(authProvider AuthProvider, msgStore msgstore.MessageStore, domainProvider DomainProvider) {
	RegisterCommand(&capaCommand{})
	RegisterCommand(&stlsCommand{})
	RegisterCommand(&userCommand{})
	RegisterCommand(&passCommand{authProvider: authProvider, msgStore: msgStore, domainProvider: domainProvider})
	RegisterCommand(&authCommand{authProvider: authProvider, msgStore: msgStore, domainProvider: domainProvider})
	RegisterCommand(&quitCommand{})
}
