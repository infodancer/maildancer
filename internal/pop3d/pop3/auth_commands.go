package pop3

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/msgstore"
)

// DomainAuthenticator handles authentication with optional domain routing.
// Implementations split user@domain usernames and route to the appropriate
// auth agent internally. Callers always pass the full username.
type DomainAuthenticator interface {
	AuthenticateWithDomain(ctx context.Context, username, password string) (*domain.AuthResult, error)
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

	// Require TLS for USER command (unless insecure auth is explicitly permitted)
	if !sess.IsTLSActive() && !sess.InsecureAuth() {
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
	auth     DomainAuthenticator
	msgStore msgstore.MessageStore
	smClient *SessionManagerClient // nil = legacy auth path
}

func (p *passCommand) Name() string {
	return "PASS"
}

func (p *passCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// PASS is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Require TLS for PASS command (unless insecure auth is explicitly permitted)
	if !sess.IsTLSActive() && !sess.InsecureAuth() {
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

	if p.smClient != nil {
		return p.executeSessionManager(ctx, sess, conn, username, password)
	}
	return p.executeLegacy(ctx, sess, conn, username, password)
}

// executeSessionManager authenticates via the session-manager service.
func (p *passCommand) executeSessionManager(ctx context.Context, sess *Session, conn ConnectionLogger, username, password string) (Response, error) {
	token, mailbox, err := p.smClient.Login(ctx, username, password)
	if err != nil {
		conn.Logger().Info("authentication failed",
			"username", username,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Authentication failed"}, nil
	}

	sess.SetAuthenticated(&auth.AuthSession{User: &auth.User{Mailbox: mailbox}})

	store := newSessionManagerStore(p.smClient, token)
	if err := sess.InitializeMailbox(ctx, store, ""); err != nil {
		conn.Logger().Error("failed to initialize mailbox",
			"username", username,
			"mailbox", mailbox,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Failed to access mailbox"}, nil
	}

	conn.Logger().Info("authentication successful",
		"username", username,
		"mailbox", mailbox,
		"via", "session-manager",
	)
	return Response{OK: true, Message: fmt.Sprintf("Logged in as %s", username)}, nil
}

// executeLegacy authenticates via the domain auth router.
func (p *passCommand) executeLegacy(ctx context.Context, sess *Session, conn ConnectionLogger, username, password string) (Response, error) {
	// Pass client IP for rate limiting.
	if ip := sess.ClientIP(); ip != "" {
		ctx = domain.WithClientIP(ctx, ip)
	}

	// Authenticate via the router (handles domain splitting internally)
	result, err := p.auth.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		conn.Logger().Info("authentication failed",
			"username", username,
			"error", err.Error(),
		)
		if errors.Is(err, autherrors.ErrRateLimited) {
			return Response{OK: false, Message: "Too many failed authentication attempts, try again later"}, nil
		}
		return Response{OK: false, Message: "Authentication failed"}, nil
	}

	sess.SetAuthenticated(result.Session)

	// Initialize mailbox: prefer domain-specific store, fall back to global
	store := p.msgStore
	if result.Domain != nil && result.Domain.MessageStore != nil {
		store = result.Domain.MessageStore
	}
	if store != nil {
		if err := sess.InitializeMailbox(ctx, store, result.Extension); err != nil {
			conn.Logger().Error("failed to initialize mailbox",
				"username", username,
				"mailbox", result.Session.User.Mailbox,
				"error", err.Error(),
			)
			return Response{OK: false, Message: "Failed to access mailbox"}, nil
		}
	}

	conn.Logger().Info("authentication successful",
		"username", username,
		"mailbox", result.Session.User.Mailbox,
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
	auth     DomainAuthenticator
	msgStore msgstore.MessageStore
	smClient *SessionManagerClient // nil = legacy auth path
}

func (a *authCommand) Name() string {
	return "AUTH"
}

func (a *authCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// AUTH is only valid in AUTHORIZATION state
	if sess.State() != StateAuthorization {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// Require TLS for AUTH command (unless insecure auth is explicitly permitted)
	if !sess.IsTLSActive() && !sess.InsecureAuth() {
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
			if a.smClient != nil {
				return a.saslSessionManager(ctx, sess, conn, mechanism, username, password)
			}
			return a.saslLegacy(ctx, sess, conn, mechanism, username, password)
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

// saslSessionManager handles SASL PLAIN via session-manager.
func (a *authCommand) saslSessionManager(ctx context.Context, sess *Session, conn ConnectionLogger, mechanism, username, password string) error {
	token, mailbox, err := a.smClient.Login(ctx, username, password)
	if err != nil {
		conn.Logger().Info("SASL authentication failed",
			"mechanism", mechanism,
			"username", username,
			"error", err.Error(),
		)
		return err
	}

	sess.SetAuthenticated(&auth.AuthSession{User: &auth.User{Mailbox: mailbox}})
	sess.SetUsername(username)

	store := newSessionManagerStore(a.smClient, token)
	if err := sess.InitializeMailbox(ctx, store, ""); err != nil {
		conn.Logger().Error("failed to initialize mailbox",
			"mechanism", mechanism,
			"username", username,
			"mailbox", mailbox,
			"error", err.Error(),
		)
		return err
	}

	conn.Logger().Info("SASL authentication successful",
		"mechanism", mechanism,
		"username", username,
		"mailbox", mailbox,
		"via", "session-manager",
	)
	return nil
}

// saslLegacy handles SASL PLAIN via the domain auth router.
func (a *authCommand) saslLegacy(ctx context.Context, sess *Session, conn ConnectionLogger, mechanism, username, password string) error {
	// Pass client IP for rate limiting.
	if ip := sess.ClientIP(); ip != "" {
		ctx = domain.WithClientIP(ctx, ip)
	}

	result, err := a.auth.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		conn.Logger().Info("SASL authentication failed",
			"mechanism", mechanism,
			"username", username,
			"error", err.Error(),
		)
		return err
	}

	sess.SetAuthenticated(result.Session)
	sess.SetUsername(username)

	store := a.msgStore
	if result.Domain != nil && result.Domain.MessageStore != nil {
		store = result.Domain.MessageStore
	}
	if store != nil {
		if err := sess.InitializeMailbox(ctx, store, result.Extension); err != nil {
			conn.Logger().Error("failed to initialize mailbox",
				"mechanism", mechanism,
				"username", username,
				"mailbox", result.Session.User.Mailbox,
				"error", err.Error(),
			)
			return err
		}
	}

	conn.Logger().Info("SASL authentication successful",
		"mechanism", mechanism,
		"username", username,
		"mailbox", result.Session.User.Mailbox,
	)
	return nil
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
// When smClient is non-nil, authentication is delegated to the session-manager
// instead of the domain auth router.
func RegisterAuthCommands(domainAuth DomainAuthenticator, msgStore msgstore.MessageStore, smClient *SessionManagerClient) {
	RegisterCommand(&capaCommand{})
	RegisterCommand(&stlsCommand{})
	RegisterCommand(&userCommand{})
	RegisterCommand(&passCommand{auth: domainAuth, msgStore: msgStore, smClient: smClient})
	RegisterCommand(&authCommand{auth: domainAuth, msgStore: msgStore, smClient: smClient})
	RegisterCommand(&quitCommand{})
}
