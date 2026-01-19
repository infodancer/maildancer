package smtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/server"
)

// Handler returns a ConnectionHandler that processes SMTP commands.
// hostname is the server's hostname for the greeting banner.
// collector is used for recording metrics (can be nil for no-op).
// delivery is used for storing messages after DATA (can be nil to reject all mail).
func Handler(hostname string, collector metrics.Collector, delivery msgstore.DeliveryAgent) server.ConnectionHandler {
	registry := NewCommandRegistry()

	return func(ctx context.Context, conn *server.Connection) {
		logger := logging.FromContext(ctx)

		// Record connection opened
		if collector != nil {
			collector.ConnectionOpened()
			defer collector.ConnectionClosed()
		}

		// Extract client IP from remote address
		clientIP := extractIP(conn.RemoteAddr())

		// Create session
		connInfo := ConnectionInfo{
			ClientIP: clientIP,
		}
		session := NewSMTPSession(connInfo, DefaultSessionConfig())

		// Send greeting
		if err := writeResponse(conn, 220, hostname+" ESMTP ready"); err != nil {
			logger.Debug("failed to send greeting", "error", err.Error())
			return
		}

		// Reset idle timeout after greeting
		if err := conn.ResetIdleTimeout(); err != nil {
			logger.Debug("failed to reset idle timeout", "error", err.Error())
			return
		}

		// Command loop
		for {
			// Read command line
			line, err := conn.Reader().ReadString('\n')
			if err != nil {
				if err != io.EOF {
					logger.Debug("failed to read command", "error", err.Error())
				}
				return
			}

			// Trim CRLF
			line = strings.TrimRight(line, "\r\n")

			if line == "" {
				continue
			}

			// Check if we're in DATA mode
			if session.InData() {
				// Collect message data
				messageData, err := collectMessageData(conn, session.Config().MaxMessageSize)
				if err != nil {
					logger.Debug("failed to collect message data", "error", err.Error())
					if err := writeResponse(conn, 451, "Error collecting message"); err != nil {
						logger.Debug("failed to write error response", "error", err.Error())
					}
					session.Reset()
					if err := conn.ResetIdleTimeout(); err != nil {
						logger.Debug("failed to reset idle timeout", "error", err.Error())
					}
					continue
				}

				// Prepend the first line (which was read as a command)
				var fullMessage bytes.Buffer
				fullMessage.WriteString(line)
				fullMessage.WriteString("\r\n")
				fullMessage.Write(messageData)

				// Deliver the message
				if delivery != nil {
					envelope := msgstore.Envelope{
						From:           session.GetSender(),
						Recipients:     session.GetRecipients(),
						ReceivedTime:   time.Now(),
						ClientIP:       net.ParseIP(clientIP),
						ClientHostname: session.GetHelo(),
					}

					if err := delivery.Deliver(ctx, envelope, &fullMessage); err != nil {
						logger.Debug("delivery failed", "error", err.Error())
						if collector != nil {
							// Use first recipient's domain for metrics
							domain := extractDomain(session.GetRecipients())
							collector.MessageRejected(domain, "delivery_error")
						}
						if err := writeResponse(conn, 451, "Delivery failed"); err != nil {
							logger.Debug("failed to write error response", "error", err.Error())
						}
					} else {
						if collector != nil {
							domain := extractDomain(session.GetRecipients())
							collector.MessageReceived(domain, int64(fullMessage.Len()))
						}
						if err := writeResponse(conn, 250, "Message queued"); err != nil {
							logger.Debug("failed to write success response", "error", err.Error())
						}
					}
				} else {
					// No delivery agent - reject all mail
					if collector != nil {
						domain := extractDomain(session.GetRecipients())
						collector.MessageRejected(domain, "no_delivery_agent")
					}
					if err := writeResponse(conn, 550, "Mail delivery not configured"); err != nil {
						logger.Debug("failed to write error response", "error", err.Error())
					}
				}

				// Reset session for next transaction
				session.Reset()
				if err := conn.ResetIdleTimeout(); err != nil {
					logger.Debug("failed to reset idle timeout", "error", err.Error())
				}
				continue
			}

			// Match command
			cmd, matches, err := registry.Match(line)
			if err != nil {
				if err := writeResponse(conn, 500, "Syntax error, command unrecognized"); err != nil {
					logger.Debug("failed to write error response", "error", err.Error())
				}
				if err := conn.ResetIdleTimeout(); err != nil {
					logger.Debug("failed to reset idle timeout", "error", err.Error())
				}
				continue
			}

			// Record command metric
			if collector != nil {
				cmdName := extractCommandName(line)
				collector.CommandProcessed(cmdName)
			}

			// Execute command
			result, execErr := cmd.Execute(ctx, session, matches)
			if execErr != nil {
				logger.Debug("command execution failed", "error", execErr.Error())
				if err := writeResponse(conn, 451, "Requested action aborted"); err != nil {
					logger.Debug("failed to write error response", "error", err.Error())
				}
				if err := conn.ResetIdleTimeout(); err != nil {
					logger.Debug("failed to reset idle timeout", "error", err.Error())
				}
				continue
			}

			// Write response
			if err := writeResponse(conn, result.Code, result.Message); err != nil {
				logger.Debug("failed to write response", "error", err.Error())
				return
			}

			// Reset idle timeout after successful command
			if err := conn.ResetIdleTimeout(); err != nil {
				logger.Debug("failed to reset idle timeout", "error", err.Error())
			}

			// Check for QUIT command
			if result.Code == 221 {
				return
			}
		}
	}
}

// writeResponse writes an SMTP response to the connection.
func writeResponse(conn *server.Connection, code int, message string) error {
	_, err := fmt.Fprintf(conn.Writer(), "%d %s\r\n", code, message)
	if err != nil {
		return err
	}
	return conn.Flush()
}

// collectMessageData reads message content until the terminating dot.
// It handles dot-stuffing per RFC 5321.
func collectMessageData(conn *server.Connection, maxSize int64) ([]byte, error) {
	var buf bytes.Buffer
	var totalSize int64

	for {
		line, err := conn.Reader().ReadString('\n')
		if err != nil {
			return nil, err
		}

		// Trim trailing newline for processing
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		// Check for terminating dot
		if line == "." {
			break
		}

		// Handle dot-stuffing: lines starting with "." have it removed
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}

		// Check size limit
		if maxSize > 0 {
			totalSize += int64(len(line)) + 2 // +2 for CRLF
			if totalSize > maxSize {
				return nil, ErrInputTooLong
			}
		}

		buf.WriteString(line)
		buf.WriteString("\r\n")
	}

	return buf.Bytes(), nil
}

// extractIP extracts the IP address string from a net.Addr.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		// Try to parse the string representation
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

// extractDomain extracts the domain from the first recipient's email address.
func extractDomain(recipients []string) string {
	if len(recipients) == 0 {
		return "unknown"
	}

	email := recipients[0]
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[idx+1:]
	}
	return "unknown"
}

// extractCommandName extracts the command name from an SMTP line for metrics.
func extractCommandName(line string) string {
	// Find the first space or end of string
	line = strings.ToUpper(line)
	if idx := strings.Index(line, " "); idx > 0 {
		return line[:idx]
	}
	return line
}
