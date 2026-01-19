package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/logging"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/infodancer/maildancer/internal/smtpd/server"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// HandlerOptions contains optional configuration for the SMTP handler.
type HandlerOptions struct {
	// SpamChecker is the spam checker for filtering (can be nil to disable).
	SpamChecker spamcheck.Checker

	// SpamCheckConfig is the spam check configuration.
	SpamCheckConfig config.SpamCheckConfig
}

// Handler returns a ConnectionHandler that processes SMTP commands.
// hostname is the server's hostname for the greeting banner.
// collector is used for recording metrics (can be nil for no-op).
// delivery is used for storing messages after DATA (can be nil to reject all mail).
// authAgent is used for SMTP authentication (can be nil to disable AUTH).
// tlsConfig is used for STARTTLS support (can be nil to disable STARTTLS).
// opts contains optional configuration (can be nil for defaults).
func Handler(hostname string, collector metrics.Collector, delivery msgstore.DeliveryAgent, authAgent auth.AuthenticationAgent, tlsConfig *tls.Config, opts *HandlerOptions) server.ConnectionHandler {
	if opts == nil {
		opts = &HandlerOptions{}
	}
	registry := NewCommandRegistry(hostname, authAgent, tlsConfig)

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

		// Initialize TLS state
		session.SetTLSActive(conn.IsTLS())

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

				// Spam check (if enabled)
				if opts.SpamChecker != nil && opts.SpamCheckConfig.IsEnabled() {
					checkResult, checkErr := opts.SpamChecker.Check(ctx, bytes.NewReader(fullMessage.Bytes()), spamcheck.CheckOptions{
						From:       session.GetSender(),
						Recipients: session.GetRecipients(),
						IP:         clientIP,
						Helo:       session.GetHelo(),
						Hostname:   hostname,
					})

					senderDomain := extractSenderDomain(session.GetSender())

					if checkErr != nil {
						// Spam check error - handle according to fail mode
						logger.Debug("spam check failed",
							"checker", opts.SpamChecker.Name(),
							"error", checkErr.Error())
						if collector != nil {
							collector.RspamdCheckCompleted(senderDomain, "error", 0)
						}

						switch opts.SpamCheckConfig.GetFailMode() {
						case config.SpamCheckFailReject:
							if collector != nil {
								domain := extractDomain(session.GetRecipients())
								collector.MessageRejected(domain, "spamcheck_error")
							}
							if err := writeResponse(conn, 550, "Spam check failed"); err != nil {
								logger.Debug("failed to write error response", "error", err.Error())
							}
							session.Reset()
							if err := conn.ResetIdleTimeout(); err != nil {
								logger.Debug("failed to reset idle timeout", "error", err.Error())
							}
							continue
						case config.SpamCheckFailTempFail:
							if collector != nil {
								domain := extractDomain(session.GetRecipients())
								collector.MessageRejected(domain, "spamcheck_error")
							}
							if err := writeResponse(conn, 451, "Temporary spam check failure, try again later"); err != nil {
								logger.Debug("failed to write error response", "error", err.Error())
							}
							session.Reset()
							if err := conn.ResetIdleTimeout(); err != nil {
								logger.Debug("failed to reset idle timeout", "error", err.Error())
							}
							continue
						default:
							// SpamCheckFailOpen - continue with delivery
							logger.Debug("spam check failed, continuing (fail open mode)")
						}
					} else {
						// Determine result for metrics
						metricResult := "ham"
						if checkResult.ShouldReject(opts.SpamCheckConfig.RejectThreshold) {
							metricResult = "spam"
						} else if checkResult.ShouldTempFail(opts.SpamCheckConfig.TempFailThreshold) {
							metricResult = "soft_reject"
						}
						if collector != nil {
							collector.RspamdCheckCompleted(senderDomain, metricResult, checkResult.Score)
						}

						logger.Debug("spam check completed",
							"checker", checkResult.CheckerName,
							"score", checkResult.Score,
							"action", checkResult.Action,
							"result", metricResult)

						// Check if message should be rejected
						if checkResult.ShouldReject(opts.SpamCheckConfig.RejectThreshold) {
							if collector != nil {
								domain := extractDomain(session.GetRecipients())
								collector.MessageRejected(domain, "spam")
							}
							rejectMsg := checkResult.RejectMessage
							if rejectMsg == "" {
								rejectMsg = fmt.Sprintf("Message rejected as spam (score %.1f)", checkResult.Score)
							}
							if err := writeResponse(conn, 550, rejectMsg); err != nil {
								logger.Debug("failed to write error response", "error", err.Error())
							}
							session.Reset()
							if err := conn.ResetIdleTimeout(); err != nil {
								logger.Debug("failed to reset idle timeout", "error", err.Error())
							}
							continue
						}

						// Check if message should be temp-failed
						if opts.SpamCheckConfig.TempFailThreshold > 0 && checkResult.ShouldTempFail(opts.SpamCheckConfig.TempFailThreshold) {
							if collector != nil {
								domain := extractDomain(session.GetRecipients())
								collector.MessageRejected(domain, "soft_reject")
							}
							rejectMsg := checkResult.RejectMessage
							if rejectMsg == "" {
								rejectMsg = "Message deferred, please try again later"
							}
							if err := writeResponse(conn, 451, rejectMsg); err != nil {
								logger.Debug("failed to write error response", "error", err.Error())
							}
							session.Reset()
							if err := conn.ResetIdleTimeout(); err != nil {
								logger.Debug("failed to reset idle timeout", "error", err.Error())
							}
							continue
						}

						// Add spam headers if configured
						if opts.SpamCheckConfig.AddHeaders && len(checkResult.Headers) > 0 {
							fullMessage = prependHeaders(fullMessage.Bytes(), checkResult.Headers)
						}
					}
				}

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
			if err := writeResult(conn, result); err != nil {
				logger.Debug("failed to write response", "error", err.Error())
				return
			}

			// Handle STARTTLS upgrade after sending 220 response
			if starttlsCmd, ok := cmd.(*STARTTLSCommand); ok && result.Code == 220 {
				if err := conn.UpgradeToTLS(starttlsCmd.TLSConfig()); err != nil {
					logger.Debug("TLS upgrade failed", "error", err.Error())
					// Connection is likely broken, close it
					return
				}

				// Record TLS established metric
				if collector != nil {
					collector.TLSConnectionEstablished()
				}

				// Update session TLS state
				session.SetTLSActive(true)

				// Per RFC 3207: Reset session state after STARTTLS
				// Client must re-issue EHLO after successful upgrade
				session.Reset()
				session.SetState(StateInit)

				logger.Debug("STARTTLS upgrade successful")
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
// For backward compatibility, accepts code and message parameters.
func writeResponse(conn *server.Connection, code int, message string) error {
	_, err := fmt.Fprintf(conn.Writer(), "%d %s\r\n", code, message)
	if err != nil {
		return err
	}
	return conn.Flush()
}

// writeResult writes an SMTP result to the connection, supporting multi-line responses.
func writeResult(conn *server.Connection, result SMTPResult) error {
	// If Lines is present, use multi-line format
	if len(result.Lines) > 0 {
		for i, line := range result.Lines {
			var err error
			if i < len(result.Lines)-1 {
				// Continuation line
				_, err = fmt.Fprintf(conn.Writer(), "%d-%s\r\n", result.Code, line)
			} else {
				// Last line
				_, err = fmt.Fprintf(conn.Writer(), "%d %s\r\n", result.Code, line)
			}
			if err != nil {
				return err
			}
		}
		return conn.Flush()
	}

	// Single-line format (backward compatible)
	return writeResponse(conn, result.Code, result.Message)
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
		line = strings.TrimPrefix(line, ".")

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

// extractSenderDomain extracts the domain from a sender email address.
func extractSenderDomain(sender string) string {
	if sender == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(sender, "@"); idx >= 0 {
		return sender[idx+1:]
	}
	return "unknown"
}

// prependHeaders prepends headers to a message.
func prependHeaders(message []byte, headers map[string]string) bytes.Buffer {
	var result bytes.Buffer

	// Find the end of existing headers (first blank line)
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		// No body separator found, treat entire message as headers
		headerEnd = len(message)
	}

	// Write existing headers
	result.Write(message[:headerEnd])

	// Add new headers before the blank line
	for name, value := range headers {
		result.WriteString("\r\n")
		result.WriteString(name)
		result.WriteString(": ")
		result.WriteString(value)
	}

	// Write the rest of the message (blank line + body)
	if headerEnd < len(message) {
		result.Write(message[headerEnd:])
	}

	return result
}
