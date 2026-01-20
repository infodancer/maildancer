package smtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// Session implements the go-smtp Session interface.
// It also implements AuthSession for AUTH support.
type Session struct {
	backend    *Backend
	conn       *smtp.Conn
	clientIP   string
	helo       string
	from       string
	recipients []string
	authUser   string
	logger     *slog.Logger
}

// AuthMechanisms returns the available authentication mechanisms.
// Implements smtp.AuthSession interface.
func (s *Session) AuthMechanisms() []string {
	if s.backend.authAgent == nil {
		return nil
	}

	// Only advertise AUTH if TLS is active or connection is from localhost
	_, isTLS := s.conn.TLSConnectionState()
	if !isTLS && !sessionIsLocalhost(s.clientIP) {
		return nil
	}

	return []string{sasl.Plain}
}

// Auth handles authentication.
// Implements smtp.AuthSession interface.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	if s.backend.authAgent == nil {
		return nil, smtp.ErrAuthUnsupported
	}

	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			ctx := context.Background()

			session, err := s.backend.authAgent.Authenticate(ctx, username, password)
			if err != nil {
				if s.backend.collector != nil {
					domain := sessionExtractAuthDomain(username)
					s.backend.collector.AuthAttempt(domain, false)
				}

				s.logger.Debug("authentication failed",
					slog.String("username", username),
					slog.String("error", err.Error()))

				if err == autherrors.ErrAuthFailed || err == autherrors.ErrUserNotFound {
					return &smtp.SMTPError{
						Code:         535,
						EnhancedCode: smtp.EnhancedCode{5, 7, 8},
						Message:      "Authentication credentials invalid",
					}
				}

				return &smtp.SMTPError{
					Code:         454,
					EnhancedCode: smtp.EnhancedCode{4, 7, 0},
					Message:      "Temporary authentication failure",
				}
			}

			if session != nil && session.User != nil {
				s.authUser = session.User.Username
			} else {
				s.authUser = username
			}

			if s.backend.collector != nil {
				domain := sessionExtractAuthDomain(username)
				s.backend.collector.AuthAttempt(domain, true)
			}

			s.logger.Debug("authentication successful", slog.String("username", s.authUser))
			return nil
		}), nil

	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

// Mail handles the MAIL FROM command.
// Implements smtp.Session interface.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("MAIL")
	}

	s.logger.Debug("MAIL FROM", slog.String("from", from))
	return nil
}

// Rcpt handles the RCPT TO command.
// Implements smtp.Session interface.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Check recipient limit
	if s.backend.maxRecipients > 0 && len(s.recipients) >= s.backend.maxRecipients {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "Too many recipients",
		}
	}

	s.recipients = append(s.recipients, to)

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("RCPT")
	}

	s.logger.Debug("RCPT TO", slog.String("to", to))
	return nil
}

// Data handles the DATA command and message delivery.
// Implements smtp.Session interface.
func (s *Session) Data(r io.Reader) error {
	ctx := context.Background()

	// Read message data
	message, err := io.ReadAll(r)
	if err != nil {
		s.logger.Debug("failed to read message data", slog.String("error", err.Error()))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Error reading message",
		}
	}

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("DATA")
	}

	// Spam check (if enabled)
	if s.backend.spamChecker != nil && s.backend.spamConfig.IsEnabled() {
		checkResult, checkErr := s.backend.spamChecker.Check(ctx, bytes.NewReader(message), spamcheck.CheckOptions{
			From:       s.from,
			Recipients: s.recipients,
			IP:         s.clientIP,
			Helo:       s.helo,
			Hostname:   s.backend.hostname,
			User:       s.authUser,
		})

		senderDomain := sessionExtractSenderDomain(s.from)

		if checkErr != nil {
			s.logger.Debug("spam check failed",
				slog.String("checker", s.backend.spamChecker.Name()),
				slog.String("error", checkErr.Error()))

			if s.backend.collector != nil {
				s.backend.collector.RspamdCheckCompleted(senderDomain, "error", 0)
			}

			switch s.backend.spamConfig.GetFailMode() {
			case config.SpamCheckFailReject:
				if s.backend.collector != nil {
					domain := sessionExtractRecipientDomain(s.recipients)
					s.backend.collector.MessageRejected(domain, "spamcheck_error")
				}
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      "Spam check failed",
				}
			case config.SpamCheckFailTempFail:
				if s.backend.collector != nil {
					domain := sessionExtractRecipientDomain(s.recipients)
					s.backend.collector.MessageRejected(domain, "spamcheck_error")
				}
				return &smtp.SMTPError{
					Code:         451,
					EnhancedCode: smtp.EnhancedCode{4, 7, 1},
					Message:      "Temporary spam check failure, try again later",
				}
			default:
				// SpamCheckFailOpen - continue with delivery
				s.logger.Debug("spam check failed, continuing (fail open mode)")
			}
		} else {
			// Determine result for metrics
			metricResult := "ham"
			if checkResult.ShouldReject(s.backend.spamConfig.RejectThreshold) {
				metricResult = "spam"
			} else if checkResult.ShouldTempFail(s.backend.spamConfig.TempFailThreshold) {
				metricResult = "soft_reject"
			}

			if s.backend.collector != nil {
				s.backend.collector.RspamdCheckCompleted(senderDomain, metricResult, checkResult.Score)
			}

			s.logger.Debug("spam check completed",
				slog.String("checker", checkResult.CheckerName),
				slog.Float64("score", checkResult.Score),
				slog.String("action", string(checkResult.Action)),
				slog.String("result", metricResult))

			// Check if message should be rejected
			if checkResult.ShouldReject(s.backend.spamConfig.RejectThreshold) {
				if s.backend.collector != nil {
					domain := sessionExtractRecipientDomain(s.recipients)
					s.backend.collector.MessageRejected(domain, "spam")
				}
				rejectMsg := checkResult.RejectMessage
				if rejectMsg == "" {
					rejectMsg = fmt.Sprintf("Message rejected as spam (score %.1f)", checkResult.Score)
				}
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      rejectMsg,
				}
			}

			// Check if message should be temp-failed
			if s.backend.spamConfig.TempFailThreshold > 0 && checkResult.ShouldTempFail(s.backend.spamConfig.TempFailThreshold) {
				if s.backend.collector != nil {
					domain := sessionExtractRecipientDomain(s.recipients)
					s.backend.collector.MessageRejected(domain, "soft_reject")
				}
				rejectMsg := checkResult.RejectMessage
				if rejectMsg == "" {
					rejectMsg = "Message deferred, please try again later"
				}
				return &smtp.SMTPError{
					Code:         451,
					EnhancedCode: smtp.EnhancedCode{4, 7, 1},
					Message:      rejectMsg,
				}
			}

			// Note: Header injection is not supported with go-smtp.
			// Spam check can reject but cannot modify the message.
		}
	}

	// Deliver the message
	if s.backend.delivery != nil {
		envelope := msgstore.Envelope{
			From:           s.from,
			Recipients:     s.recipients,
			ReceivedTime:   time.Now(),
			ClientIP:       net.ParseIP(s.clientIP),
			ClientHostname: s.helo,
		}

		messageReader := bytes.NewReader(message)
		if err := s.backend.delivery.Deliver(ctx, envelope, messageReader); err != nil {
			s.logger.Debug("delivery failed", slog.String("error", err.Error()))

			if s.backend.collector != nil {
				domain := sessionExtractRecipientDomain(s.recipients)
				s.backend.collector.MessageRejected(domain, "delivery_error")
			}

			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Delivery failed",
			}
		}

		if s.backend.collector != nil {
			domain := sessionExtractRecipientDomain(s.recipients)
			s.backend.collector.MessageReceived(domain, int64(len(message)))
		}

		s.logger.Debug("message delivered",
			slog.Int("size", len(message)),
			slog.Int("recipients", len(s.recipients)))
	} else {
		// No delivery agent - reject all mail
		if s.backend.collector != nil {
			domain := sessionExtractRecipientDomain(s.recipients)
			s.backend.collector.MessageRejected(domain, "no_delivery_agent")
		}
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Mail delivery not configured",
		}
	}

	return nil
}

// Reset is called when the client sends RSET.
// Implements smtp.Session interface.
func (s *Session) Reset() {
	s.from = ""
	s.recipients = nil
	s.logger.Debug("session reset")
}

// Logout is called when the client quits or the connection closes.
// Implements smtp.Session interface.
func (s *Session) Logout() error {
	if s.backend.collector != nil {
		s.backend.collector.ConnectionClosed()
	}
	s.logger.Debug("session logout")
	return nil
}

// sessionExtractRecipientDomain extracts the domain from the first recipient's email address.
func sessionExtractRecipientDomain(recipients []string) string {
	if len(recipients) == 0 {
		return "unknown"
	}

	email := recipients[0]
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[idx+1:]
	}
	return "unknown"
}

// sessionExtractSenderDomain extracts the domain from a sender email address.
func sessionExtractSenderDomain(sender string) string {
	if sender == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(sender, "@"); idx >= 0 {
		return sender[idx+1:]
	}
	return "unknown"
}

// sessionExtractAuthDomain extracts the domain from an authentication username.
func sessionExtractAuthDomain(username string) string {
	if username == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[idx+1:]
	}
	return "local"
}

// sessionIsLocalhost checks if the given IP address is a localhost address.
func sessionIsLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" ||
		(len(ip) > 4 && ip[:4] == "127.") || ip == "localhost"
}
