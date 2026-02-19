package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/logging"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
	"github.com/infodancer/maildancer/internal/imapd/server"
	"github.com/infodancer/maildancer/msgstore"
)

// DomainAuthenticator handles authentication with optional domain routing.
type DomainAuthenticator interface {
	AuthenticateWithDomain(ctx context.Context, username, password string) (*domain.AuthResult, error)
}

// Handler creates an IMAP protocol handler with the given configuration.
func Handler(cfg *config.Config, tlsConfig *tls.Config, authRouter DomainAuthenticator, store msgstore.MessageStore, collector metrics.Collector) server.ConnectionHandler {
	// Register all commands
	registerAllCommands(authRouter, store)

	return func(ctx context.Context, conn *server.Connection) {
		handleConnection(ctx, conn, cfg, tlsConfig, authRouter, store, collector)
	}
}

// registerAllCommands registers all IMAP commands.
func registerAllCommands(auth DomainAuthenticator, store msgstore.MessageStore) {
	// Common commands (any state)
	RegisterCommand(&capabilityCommand{})
	RegisterCommand(&noopCommand{})
	RegisterCommand(&logoutCommand{})
	RegisterCommand(&checkCommand{})

	// Not-Authenticated state
	RegisterCommand(&starttlsCommand{})
	RegisterCommand(&authenticateCommand{auth: auth, store: store})
	RegisterCommand(&loginCommand{auth: auth, store: store})

	// Authenticated state
	RegisterCommand(&selectCommand{})
	RegisterCommand(&examineCommand{})
	RegisterCommand(&createCommand{})
	RegisterCommand(&deleteCommand{})
	RegisterCommand(&renameCommand{})
	RegisterCommand(&subscribeCommand{})
	RegisterCommand(&unsubscribeCommand{})
	RegisterCommand(&listCommand{})
	RegisterCommand(&lsubCommand{})
	RegisterCommand(&statusCommand{})
	RegisterCommand(&appendCommand{})
	RegisterCommand(&closeCommand{})
	RegisterCommand(&expungeCommand{})

	// Selected state
	RegisterCommand(&searchCommand{})
	RegisterCommand(&fetchCommand{})
	RegisterCommand(&storeCommand{})
	RegisterCommand(&copyCommand{})
	RegisterCommand(&uidCommand{})
}

// handleConnection manages a single IMAP connection.
func handleConnection(ctx context.Context, conn *server.Connection, cfg *config.Config, tlsConfig *tls.Config, authRouter DomainAuthenticator, store msgstore.MessageStore, collector metrics.Collector) {
	logger := logging.FromContext(ctx)

	// Record connection opened
	collector.ConnectionOpened()
	defer collector.ConnectionClosed()

	// Determine listener mode
	listenerMode := config.ModeImap
	if conn.IsTLS() {
		listenerMode = config.ModeImaps
		collector.TLSConnectionEstablished()
	}

	// Create session
	sess := NewSession(cfg.Hostname, listenerMode, tlsConfig, conn.IsTLS(), store, collector, logger)
	defer sess.Cleanup()

	logger.Info("starting IMAP session",
		"state", sess.State().String(),
	)

	// Send greeting with capabilities
	caps := sess.Capabilities(conn.IsTLS())
	greeting := fmt.Sprintf("OK [CAPABILITY %s] %s IMAP4rev1 server ready", strings.Join(caps, " "), cfg.Hostname)
	if err := writeUntagged(conn.Writer(), greeting); err != nil {
		logger.Error("failed to send greeting", "error", err.Error())
		return
	}
	if err := flushConn(conn); err != nil {
		logger.Error("failed to flush greeting", "error", err.Error())
		return
	}

	// Command loop
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			logger.Info("context cancelled, closing connection")
			return
		default:
		}

		if conn.IsClosed() {
			return
		}

		// Set command timeout
		if err := conn.SetCommandTimeout(); err != nil {
			logger.Error("failed to set command timeout", "error", err.Error())
			return
		}

		// Read command line
		line, err := conn.Reader().ReadString('\n')
		if err != nil {
			if err == io.EOF {
				logger.Info("client closed connection")
				return
			}
			logger.Error("error reading command", "error", err.Error())
			return
		}

		// Reset idle timeout after successful read
		if err := conn.ResetIdleTimeout(); err != nil {
			logger.Error("failed to reset idle timeout", "error", err.Error())
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		logger.Debug("received command", "line", line)

		// Parse command line
		parsed, err := ParseCommandLine(line)
		if err != nil {
			if writeErr := writeUntagged(conn.Writer(), "BAD "+err.Error()); writeErr != nil {
				logger.Error("failed to send error", "error", writeErr.Error())
				return
			}
			_ = flushConn(conn)
			continue
		}

		// Handle UID prefix
		cmdName := parsed.Name
		cmdArgs := parsed.Args
		tag := parsed.Tag

		// Look up command
		cmd, ok := GetCommand(cmdName)
		if !ok {
			if writeErr := writeBAD(conn.Writer(), tag, "Unknown command"); writeErr != nil {
				logger.Error("failed to send error", "error", writeErr.Error())
				return
			}
			_ = flushConn(conn)
			continue
		}

		logger.Debug("executing command",
			"command", cmdName,
			"tag", tag,
		)

		// Record command
		collector.CommandProcessed(cmdName)

		// Execute command
		if err := cmd.Execute(ctx, tag, cmdArgs, sess, conn); err != nil {
			logger.Error("command execution error",
				"command", cmdName,
				"error", err.Error(),
			)
			if writeErr := writeBAD(conn.Writer(), tag, "Internal server error"); writeErr != nil {
				logger.Error("failed to send error", "error", writeErr.Error())
				return
			}
		}

		if err := flushConn(conn); err != nil {
			logger.Error("failed to flush response", "error", err.Error())
			return
		}

		// Check for logout
		if sess.State() == StateLogout {
			logger.Info("LOGOUT, closing connection")
			return
		}
	}
}
