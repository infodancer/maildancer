package pop3

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/smclient"
	"github.com/infodancer/maildancer/msgstore"
)

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
	smClient         *SessionManagerClient
	recoveryDeadline time.Duration
	collector        metrics.Collector
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

	mailbox, store, err := loginRecoveringSession(ctx, p.smClient, p.recoveryDeadline, p.collector, username, password, sess.ClientIP())
	if err != nil {
		conn.Logger().Info("authentication failed",
			"username", username,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Authentication failed"}, nil
	}

	sess.SetAuthenticated(AuthenticatedUser{Username: username, Mailbox: mailbox})

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
		// Enter UPDATE state and commit deletions BEFORE answering: RFC
		// 1939's UPDATE state completes before the response, and a failed
		// commit must surface as -ERR so the client keeps its DELE state
		// and can retry after reconnecting (session-recovery-design.md;
		// previously the +OK was sent first and commit errors were
		// silently dropped).
		sess.EnterUpdate()
		if store := sess.Store(); store != nil {
			if err := commitDeletions(ctx, sess, conn, store); err != nil {
				return Response{OK: false, Message: "[SYS/TEMP] some deleted messages not removed"}, nil
			}
		}
		message = "Logging out"

	default:
		message = "Goodbye"
	}

	return Response{OK: true, Message: message}, nil
}

// authCommand implements the AUTH command (RFC 5034).
type authCommand struct {
	smClient         *SessionManagerClient
	recoveryDeadline time.Duration
	collector        metrics.Collector
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
			return a.saslAuthenticate(ctx, sess, conn, mechanism, username, password)
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

// saslAuthenticate handles SASL PLAIN via session-manager.
func (a *authCommand) saslAuthenticate(ctx context.Context, sess *Session, conn ConnectionLogger, mechanism, username, password string) error {
	mailbox, store, err := loginRecoveringSession(ctx, a.smClient, a.recoveryDeadline, a.collector, username, password, sess.ClientIP())
	if err != nil {
		conn.Logger().Info("SASL authentication failed",
			"mechanism", mechanism,
			"username", username,
			"error", err.Error(),
		)
		return err
	}

	sess.SetAuthenticated(AuthenticatedUser{Username: username, Mailbox: mailbox})
	sess.SetUsername(username)

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

// loginRecoveringSession authenticates through a recovering smclient.Session
// that retains the presented credential for the lifetime of this one
// connection (zeroed on close), enabling transparent recovery across a
// session-manager restart (#179, session-recovery-design.md).
func loginRecoveringSession(ctx context.Context, client *SessionManagerClient, deadline time.Duration, collector metrics.Collector, username, password, clientIP string) (string, *sessionManagerStore, error) {
	smSess := smclient.NewSession(client, smclient.SessionConfig{RecoveryDeadline: deadline}, nil)
	if collector != nil {
		smSess.SetRecoveryMetric(collector.SessionRecovery)
	}
	mailbox, err := smSess.Login(ctx, username, password, clientIP)
	if err != nil {
		return "", nil, err
	}
	return mailbox, newSessionManagerStore(smSess), nil
}

// RegisterAuthCommands registers all authentication-related commands.
// Authentication is delegated to the session-manager via smClient.
func RegisterAuthCommands(smClient *SessionManagerClient, recoveryDeadline time.Duration, collector metrics.Collector) {
	RegisterCommand(&capaCommand{})
	RegisterCommand(&stlsCommand{})
	RegisterCommand(&userCommand{})
	RegisterCommand(&passCommand{smClient: smClient, recoveryDeadline: recoveryDeadline, collector: collector})
	RegisterCommand(&authCommand{smClient: smClient, recoveryDeadline: recoveryDeadline, collector: collector})
	RegisterCommand(&quitCommand{})
}

// commitDeletions applies the session's pending DELE marks: one Delete RPC
// per UID, then a single Expunge. RPCs go through the recovering session, so
// a session-manager restart mid-commit is retried transparently where safe
// (the writes themselves are at-most-once); any remaining failure is
// returned so QUIT answers -ERR.
func commitDeletions(ctx context.Context, sess *Session, conn ConnectionLogger, store msgstore.MessageStore) error {
	uids := sess.GetDeletedUIDs()
	if len(uids) == 0 {
		return nil
	}
	var firstErr error
	for _, uid := range uids {
		if err := store.Delete(ctx, sess.Mailbox(), uid); err != nil {
			conn.Logger().Error("failed to delete message", "uid", uid, "error", err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := store.Expunge(ctx, sess.Mailbox()); err != nil {
		conn.Logger().Error("failed to expunge mailbox", "error", err.Error())
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		conn.Logger().Info("expunged messages", "count", len(uids))
	}
	return firstErr
}
