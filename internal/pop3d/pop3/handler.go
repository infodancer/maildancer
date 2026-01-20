package pop3

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/logging"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/server"
)

// Handler creates a POP3 protocol handler with the given configuration.
func Handler(hostname string, authProvider AuthProvider, msgStore msgstore.MessageStore, tlsConfig *tls.Config, collector metrics.Collector) server.ConnectionHandler {
	// Register authentication commands with the auth provider and message store
	RegisterAuthCommands(authProvider, msgStore)
	// Register transaction commands
	RegisterTransactionCommands()

	return func(ctx context.Context, conn *server.Connection) {
		handleConnection(ctx, conn, hostname, msgStore, tlsConfig, collector)
	}
}

// handleConnection manages a single POP3 connection.
func handleConnection(ctx context.Context, conn *server.Connection, hostname string, msgStore msgstore.MessageStore, tlsConfig *tls.Config, collector metrics.Collector) {
	logger := logging.FromContext(ctx)

	// Record connection opened
	collector.ConnectionOpened()
	defer collector.ConnectionClosed()

	// Determine listener mode based on connection state
	// If already TLS, assume ModePop3s; otherwise ModePop3
	listenerMode := config.ModePop3
	if conn.IsTLS() {
		listenerMode = config.ModePop3s
		collector.TLSConnectionEstablished()
	}

	// Create session
	sess := NewSession(hostname, listenerMode, tlsConfig, conn.IsTLS())
	defer sess.Cleanup()

	logger.Info("starting POP3 session",
		"state", sess.State().String(),
		"tls_state", sess.TLSState().String(),
	)

	// Send greeting
	greeting := fmt.Sprintf("+OK %s POP3 server ready\r\n", hostname)
	if _, err := conn.Writer().WriteString(greeting); err != nil {
		logger.Error("failed to send greeting", "error", err.Error())
		return
	}
	if err := conn.Flush(); err != nil {
		logger.Error("failed to flush greeting", "error", err.Error())
		return
	}

	// Command loop
	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			logger.Info("context cancelled, closing connection")
			return
		default:
		}

		// Check if connection is closed
		if conn.IsClosed() {
			logger.Info("connection closed")
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

		// Trim whitespace
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		logger.Debug("received command", "line", line)

		// Parse command
		cmdName, args, err := ParseCommand(line)
		if err != nil {
			sendError(conn, logger, "Invalid command")
			continue
		}

		// Look up command
		cmd, ok := GetCommand(cmdName)
		if !ok {
			sendError(conn, logger, "Unknown command")
			continue
		}

		logger.Debug("executing command",
			"command", cmdName,
			"args_count", len(args),
		)

		// Record command execution
		collector.CommandProcessed(cmdName)

		// Execute command
		resp, err := cmd.Execute(ctx, sess, conn, args)
		if err != nil {
			logger.Error("command execution error",
				"command", cmdName,
				"error", err.Error(),
			)
			sendError(conn, logger, "Internal server error")
			continue
		}

		// Send response
		if _, err := conn.Writer().WriteString(resp.String()); err != nil {
			logger.Error("failed to send response", "error", err.Error())
			return
		}
		if err := conn.Flush(); err != nil {
			logger.Error("failed to flush response", "error", err.Error())
			return
		}

		logger.Debug("sent response",
			"ok", resp.OK,
			"message", resp.Message,
		)

		// Record auth metrics for PASS command
		if cmdName == "PASS" {
			domain := extractDomain(sess.Username())
			collector.AuthAttempt(domain, resp.OK)
		}

		// Handle special cases
		switch cmdName {
		case "STLS":
			// If STLS succeeded, upgrade the connection to TLS
			if resp.OK {
				if err := upgradeToTLS(ctx, conn, sess); err != nil {
					logger.Error("TLS upgrade failed", "error", err.Error())
					return
				}
				collector.TLSConnectionEstablished()
				logger.Info("TLS upgrade successful",
					"tls_state", sess.TLSState().String(),
				)
			}

		case "QUIT":
			// If we were in TRANSACTION state (now UPDATE), expunge deleted messages
			if sess.State() == StateUpdate && msgStore != nil {
				uids := sess.GetDeletedUIDs()
				for _, uid := range uids {
					if err := msgStore.Delete(ctx, sess.Mailbox(), uid); err != nil {
						logger.Error("failed to delete message", "uid", uid, "error", err.Error())
					}
				}
				if len(uids) > 0 {
					if err := msgStore.Expunge(ctx, sess.Mailbox()); err != nil {
						logger.Error("failed to expunge mailbox", "error", err.Error())
					} else {
						logger.Info("expunged messages", "count", len(uids))
					}
				}
			}
			logger.Info("QUIT command received, closing connection")
			return
		}
	}
}

// upgradeToTLS performs the TLS upgrade after STLS command.
func upgradeToTLS(ctx context.Context, conn *server.Connection, sess *Session) error {
	logger := logging.FromContext(ctx)

	tlsConfig := sess.TLSConfig()
	if tlsConfig == nil {
		return fmt.Errorf("no TLS configuration available")
	}

	logger.Info("upgrading connection to TLS")

	// Perform TLS upgrade on the connection
	if err := conn.UpgradeToTLS(tlsConfig); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Update session state
	sess.SetTLSActive()

	return nil
}

// sendError sends an error response to the client.
func sendError(conn *server.Connection, logger interface{}, message string) {
	resp := Response{OK: false, Message: message}
	if _, err := conn.Writer().WriteString(resp.String()); err != nil {
		return
	}
	_ = conn.Flush()
}

// extractDomain extracts the domain part from a username.
// If the username contains @, returns the part after @.
// Otherwise returns "unknown" for metrics labeling.
func extractDomain(username string) string {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[idx+1:]
	}
	return "unknown"
}
