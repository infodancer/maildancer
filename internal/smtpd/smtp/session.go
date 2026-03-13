package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// tempBuffer abstracts temporary message storage during DATA processing.
// The preferred implementation writes to a temp file on the mail store
// filesystem so the delivery agent can do an atomic rename. If filesystem
// access fails, the fallback holds the message in memory.
type tempBuffer interface {
	io.Writer
	// reader returns an io.Reader positioned at the start of the written data.
	reader() io.Reader
	// cleanup releases any held resources (close + unlink for file; noop for mem).
	cleanup()
}

type fileTempBuf struct{ f *os.File }

func (b *fileTempBuf) Write(p []byte) (int, error) { return b.f.Write(p) }
func (b *fileTempBuf) reader() io.Reader {
	_, _ = b.f.Seek(0, io.SeekStart)
	return b.f
}
func (b *fileTempBuf) cleanup() {
	_ = b.f.Close()
	_ = os.Remove(b.f.Name())
}

type memTempBuf struct{ buf bytes.Buffer }

func (b *memTempBuf) Write(p []byte) (int, error) { return b.buf.Write(p) }
func (b *memTempBuf) reader() io.Reader           { return bytes.NewReader(b.buf.Bytes()) }
func (b *memTempBuf) cleanup()                    {}

// newTempBuffer tries to create a temp file in dir (falling back to os.TempDir
// when dir is ""). If file creation fails for any reason, it returns an
// in-memory buffer so message delivery can still proceed.
func newTempBuffer(dir string) tempBuffer {
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err == nil {
			if f, err := os.CreateTemp(dir, "smtp-msg-*"); err == nil {
				return &fileTempBuf{f: f}
			}
		}
	} else {
		if f, err := os.CreateTemp("", "smtp-msg-*"); err == nil {
			return &fileTempBuf{f: f}
		}
	}
	return &memTempBuf{}
}

// countingReader wraps an io.Reader and counts bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Session implements the go-smtp Session interface.
// It also implements AuthSession for AUTH support.
type Session struct {
	backend                  *Backend
	conn                     *smtp.Conn
	clientIP                 string
	helo                     string
	from                     string
	mailFromSeen             bool     // true once MAIL FROM is accepted (from may be "" for bounces)
	recipients               []string // local recipients → mail-session
	remoteRecipients         []string // remote recipients → queue (authenticated submission only)
	authUser                 string
	domain                   *domain.Domain // Set during RCPT TO for delivery
	deferredInvalidRecipient string         // non-empty when data-mode deferred an unknown user
	logger                   *slog.Logger
}

// AuthMechanisms returns the available authentication mechanisms.
// Implements smtp.AuthSession interface.
func (s *Session) AuthMechanisms() []string {
	// Only advertise AUTH if TLS is active or connection is from localhost.
	// Check both go-smtp's TLS detection and the underlying connection,
	// because implicit TLS connections (port 465) wrapped in notifyConn
	// are not detected by go-smtp's direct *tls.Conn type assertion.
	isTLS := sessionConnIsTLS(s.conn)
	if !isTLS && !sessionIsLocalhost(s.clientIP) {
		return nil
	}

	var mechs []string

	// Advertise PLAIN if password auth is configured
	if s.backend.authAgent != nil {
		mechs = append(mechs, sasl.Plain)
	}

	// Advertise OAUTHBEARER if OAuth is configured
	if s.backend.oauthAgent != nil {
		mechs = append(mechs, sasl.OAuthBearer)
	}

	return mechs
}

// Auth handles authentication.
// Implements smtp.AuthSession interface.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		if s.backend.authAgent == nil {
			return nil, smtp.ErrAuthUnsupported
		}

		return sasl.NewPlainServer(func(identity, username, password string) error {
			ctx := context.Background()

			// Pass client IP for rate limiting.
			if s.clientIP != "" {
				ctx = domain.WithClientIP(ctx, s.clientIP)
			}

			// AuthRouter handles domain splitting for user@domain usernames
			_, err := s.backend.authRouter.Authenticate(ctx, username, password)
			if err != nil {
				if s.backend.collector != nil {
					domain := sessionExtractAuthDomain(username)
					s.backend.collector.AuthAttempt(domain, false)
				}

				s.logger.Debug("authentication failed",
					slog.String("username", username),
					slog.String("error", err.Error()))

				if err == autherrors.ErrRateLimited {
					return &smtp.SMTPError{
						Code:         421,
						EnhancedCode: smtp.EnhancedCode{4, 7, 0},
						Message:      "Too many failed authentication attempts, try again later",
					}
				}

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

			// Always use the full login username (user@domain) for sender
			// verification. The auth session's User.Username may be the
			// bare local part without domain.
			s.authUser = username

			if s.backend.collector != nil {
				domain := sessionExtractAuthDomain(username)
				s.backend.collector.AuthAttempt(domain, true)
			}

			s.logger = s.logger.With(slog.String("auth_user", s.authUser))
			s.logger.Info("authentication successful")
			return nil
		}), nil

	case sasl.OAuthBearer:
		if s.backend.oauthAgent == nil {
			return nil, smtp.ErrAuthUnsupported
		}

		return sasl.NewOAuthBearerServer(func(opts sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
			ctx := context.Background()

			username, err := s.backend.oauthAgent.ValidateToken(ctx, opts.Token)
			if err != nil {
				if s.backend.collector != nil {
					// Use username from options if available, otherwise "unknown"
					authDomain := "unknown"
					if opts.Username != "" {
						authDomain = sessionExtractAuthDomain(opts.Username)
					}
					s.backend.collector.AuthAttempt(authDomain, false)
				}

				s.logger.Debug("OAuth authentication failed",
					slog.String("username", opts.Username),
					slog.String("error", err.Error()))

				// Return OAuth-specific error per RFC 7628
				return &sasl.OAuthBearerError{
					Status:  "invalid_token",
					Schemes: "bearer",
				}
			}

			s.authUser = username

			if s.backend.collector != nil {
				domain := sessionExtractAuthDomain(username)
				s.backend.collector.AuthAttempt(domain, true)
			}

			s.logger = s.logger.With(slog.String("auth_user", s.authUser))
			s.logger.Info("OAuth authentication successful")
			return nil
		}), nil

	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

// Mail handles the MAIL FROM command.
// Implements smtp.Session interface.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// Per-sender rate limiting for authenticated submission (Redis-backed).
	// Resolves per-domain limit from DomainConfig.Limits with global fallback.
	if s.authUser != "" && s.backend.senderRateLimiter != nil {
		maxRate := s.backend.maxSendsPerHour
		if senderDomain := extractDomain(s.authUser); senderDomain != "" {
			if dp := s.backend.domainProvider; dp != nil {
				if dom := dp.GetDomain(senderDomain); dom != nil && dom.Limits.MaxSendsPerHour > 0 {
					maxRate = dom.Limits.MaxSendsPerHour
				}
			}
		}
		if maxRate > 0 && !s.backend.senderRateLimiter.allow(context.Background(), s.authUser, maxRate) {
			s.logger.Warn("sender rate limit exceeded",
				slog.String("auth_user", s.authUser))
			return &smtp.SMTPError{
				Code:         452,
				EnhancedCode: smtp.EnhancedCode{4, 7, 1},
				Message:      "Too many messages, try again later",
			}
		}
	}

	// Sender verification: authenticated users may only send as their exact
	// authenticated address. No aliases, no other local parts on the same domain.
	// Bounce messages (empty sender) are exempt.
	if s.authUser != "" && from != "" {
		// Normalize both addresses: strip angle brackets, lowercase.
		normFrom := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(from, "<"), ">"))
		normAuth := strings.ToLower(s.authUser)
		if normFrom != normAuth {
			s.logger.Warn("sender verification failed",
				slog.String("auth_user", s.authUser),
				slog.String("from", from))
			return &smtp.SMTPError{
				Code:         553,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "Sender address not authorized for this account",
			}
		}
	}

	s.from = from
	s.mailFromSeen = true

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("MAIL")
	}

	s.logger.Info("MAIL FROM", slog.String("from", from))
	return nil
}

// Rcpt handles the RCPT TO command.
// Implements smtp.Session interface.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Enforce single recipient per message to avoid partial delivery scenarios.
	// Remote (queued) recipients and deferred-invalid count against the same limit.
	if len(s.recipients)+len(s.remoteRecipients) > 0 || s.deferredInvalidRecipient != "" {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "One recipient at a time",
		}
	}

	// Extract domain from address
	domainName := extractDomain(to)
	if domainName == "" {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 2},
			Message:      "Invalid address format",
		}
	}

	// Validate domain if DomainProvider is configured
	if s.backend.domainProvider != nil {
		d := s.backend.domainProvider.GetDomain(domainName)
		if d == nil {
			// Domain is not local. Allow relay only for authenticated senders.
			if s.authUser == "" {
				s.logger.Debug("relay denied: unauthenticated", slog.String("domain", domainName))
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      "Relay denied",
				}
			}
			// Authenticated submission: queue for remote delivery.
			s.remoteRecipients = append(s.remoteRecipients, to)
			if s.backend.collector != nil {
				s.backend.collector.CommandProcessed("RCPT")
			}
			s.logger.Info("RCPT TO (remote)", slog.String("from", s.from), slog.String("to", to))
			return nil
		}

		// Check if user exists (AuthRouter handles domain splitting)
		ctx := context.Background()
		exists, err := s.backend.authRouter.UserExists(ctx, to)
		if err != nil {
			s.logger.Debug("user lookup failed",
				slog.String("recipient", to),
				slog.String("error", err.Error()))
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Temporary lookup failure",
			}
		}

		if !exists {
			// Determine rejection mode: per-domain overrides global.
			mode := s.backend.rejectionMode
			if d.RecipientRejection != "" {
				mode = config.RejectionMode(d.RecipientRejection)
			}

			if mode == config.RejectionModeData {
				// Defer rejection to after DATA to hide address validity
				// and enable spamtrap auto-learning.
				s.deferredInvalidRecipient = to
				s.domain = d
				s.logger.Debug("RCPT TO (deferred rejection)",
					slog.String("to", to), slog.String("mode", "data"))

				if s.backend.collector != nil {
					s.backend.collector.CommandProcessed("RCPT")
				}
				return nil
			}

			s.logger.Debug("user unknown", slog.String("recipient", to))
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "User unknown",
			}
		}

		// Fail early: verify delivery is possible before accepting the recipient.
		// Returning a temp fail lets the sender retry rather than lose the message.
		if d.DeliveryAgent == nil && s.backend.delivery == nil && s.backend.smDelivery == nil {
			s.logger.Debug("no delivery agent for domain", slog.String("domain", domainName))
			return &smtp.SMTPError{
				Code:         452,
				EnhancedCode: smtp.EnhancedCode{4, 3, 5},
				Message:      "Delivery not available, try again later",
			}
		}

		s.domain = d // Store for delivery
	}

	s.recipients = append(s.recipients, to)

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("RCPT")
	}

	s.logger.Info("RCPT TO (local)", slog.String("from", s.from), slog.String("to", to))
	return nil
}

// extractDomain extracts the domain part from an email address.
func extractDomain(email string) string {
	// Handle angle brackets: <user@domain>
	email = strings.TrimPrefix(email, "<")
	email = strings.TrimSuffix(email, ">")

	idx := strings.LastIndex(email, "@")
	if idx < 0 || idx == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[idx+1:])
}

// checkFromAlignment parses the RFC 5322 From header and verifies it exactly
// matches the envelope sender (and therefore the authenticated user). This
// enforces both DMARC alignment and prevents header forgery — the DKIM
// signature domain will match the From header domain at the receiving MTA.
func (s *Session) checkFromAlignment(r io.Reader) error {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		s.logger.Warn("failed to parse message headers",
			slog.String("error", err.Error()))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "Message headers could not be parsed",
		}
	}

	fromHeader := msg.Header.Get("From")
	if fromHeader == "" {
		s.logger.Warn("missing From header in outbound message")
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "Message must contain a From header",
		}
	}

	addrs, err := mail.ParseAddressList(fromHeader)
	if err != nil || len(addrs) == 0 {
		s.logger.Warn("invalid From header",
			slog.String("from_header", fromHeader),
			slog.String("error", err.Error()))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "From header address is invalid",
		}
	}

	if len(addrs) > 1 {
		s.logger.Warn("multiple From addresses in outbound message",
			slog.String("from_header", fromHeader))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "Message must have exactly one From address",
		}
	}

	// Exact address match: From header must be the authenticated sender.
	// Same policy as envelope sender verification in Mail().
	normFrom := strings.ToLower(addrs[0].Address)
	normEnvelope := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(s.from, "<"), ">"))

	if normFrom != normEnvelope {
		s.logger.Warn("From header does not match envelope sender",
			slog.String("header_from", addrs[0].Address),
			slog.String("envelope_from", s.from),
			slog.String("auth_user", s.authUser))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "From header must match the authenticated sender address",
		}
	}

	return nil
}

// Data handles the DATA command and message delivery.
// Implements smtp.Session interface.
//
// Uses TeeReader to stream message data to a temp file during spam checking,
// avoiding triple buffering of large messages in memory.
func (s *Session) Data(r io.Reader) error {
	ctx := context.Background()

	if s.backend.collector != nil {
		s.backend.collector.CommandProcessed("DATA")
	}

	// Validate session state before reading any message data (fail early).
	// Note: s.from may be "" for bounce messages (MAIL FROM:<>), so we track
	// whether MAIL FROM was seen separately.
	if !s.mailFromSeen {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands: MAIL FROM required",
		}
	}
	if len(s.recipients)+len(s.remoteRecipients) == 0 && s.deferredInvalidRecipient == "" {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands: RCPT TO required",
		}
	}

	// Resolve the local delivery agent (only needed if we have local recipients).
	// Fail early to avoid buffering the body only to discard it.
	// Session-manager takes priority — it has no msgstore dependency.
	useSessionManager := s.backend.smDelivery != nil
	var deliveryAgent msgstore.DeliveryAgent
	if len(s.recipients) > 0 && !useSessionManager {
		if s.domain != nil && s.domain.DeliveryAgent != nil {
			deliveryAgent = s.domain.DeliveryAgent
		} else if s.backend.delivery != nil {
			deliveryAgent = s.backend.delivery
		}
		if deliveryAgent == nil {
			s.logger.Debug("no delivery agent configured")
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Delivery not configured, try again later",
			}
		}
	}

	// For remote-only delivery, ensure session-manager is configured.
	if len(s.recipients) == 0 && len(s.remoteRecipients) > 0 && s.backend.smDelivery == nil {
		s.logger.Debug("session-manager not configured for remote delivery")
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Remote delivery not available, try again later",
		}
	}

	// Buffer the message data. Prefer a temp file on the mail store filesystem
	// (Maildir spec: tmp/ on same device enables atomic rename). Falls back to
	// an in-memory buffer if file creation fails (e.g. read-only filesystem,
	// scratch container with no /tmp configured).
	tmp := newTempBuffer(s.backend.tempDir)
	defer tmp.cleanup()

	// TeeReader writes to tmp as data is read
	tee := io.TeeReader(r, tmp)

	// Wrap in countingReader to track message size
	counter := &countingReader{r: tee}

	// Spam check (if enabled) - reads through counter, which fills tmpFile
	var checkResult *spamcheck.CheckResult
	if s.backend.spamChecker != nil && s.backend.spamConfig.IsEnabled() {
		var checkErr error
		checkResult, checkErr = s.backend.spamChecker.Check(ctx, counter, spamcheck.CheckOptions{
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
				s.logger.Debug("message rejected as spam",
					slog.Float64("score", checkResult.Score),
					slog.String("action", string(checkResult.Action)),
					slog.String("reason", checkResult.RejectMessage))
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message:      "Message rejected",
				}
			}

			// Check if message should be temp-failed
			if s.backend.spamConfig.TempFailThreshold > 0 && checkResult.ShouldTempFail(s.backend.spamConfig.TempFailThreshold) {
				if s.backend.collector != nil {
					domain := sessionExtractRecipientDomain(s.recipients)
					s.backend.collector.MessageRejected(domain, "soft_reject")
				}
				s.logger.Debug("message deferred by spam check",
					slog.Float64("score", checkResult.Score),
					slog.String("action", string(checkResult.Action)),
					slog.String("reason", checkResult.RejectMessage))
				return &smtp.SMTPError{
					Code:         451,
					EnhancedCode: smtp.EnhancedCode{4, 7, 1},
					Message:      "Message deferred, please try again later",
				}
			}

			// checkResult is used below for the delivery envelope.
		}
	} else {
		// No spam check - read the entire message into tmp
		if _, err := io.Copy(tmp, counter); err != nil {
			s.logger.Debug("failed to read message data", slog.String("error", err.Error()))
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Error reading message",
			}
		}
	}

	// Deferred rejection: recipient was accepted at RCPT TO in data-mode
	// but is actually invalid. Auto-learn as spam, then reject.
	if s.deferredInvalidRecipient != "" {
		recipientDomain := sessionExtractRecipientDomain([]string{s.deferredInvalidRecipient})
		spamAlreadyRejected := checkResult != nil && checkResult.ShouldReject(s.backend.spamConfig.RejectThreshold)

		if s.backend.spamtrapLearner != nil && !spamAlreadyRejected {
			if s.backend.spamtrapRateLimiter.allow(s.clientIP) {
				if err := s.backend.spamtrapLearner.learnSpam(ctx, s.deferredInvalidRecipient, tmp.reader()); err != nil {
					s.logger.Warn("spamtrap auto-learn failed",
						slog.String("recipient", s.deferredInvalidRecipient),
						slog.String("error", err.Error()))
				} else {
					s.logger.Info("spamtrap auto-learn: trained as spam",
						slog.String("recipient", s.deferredInvalidRecipient),
						slog.String("client_ip", s.clientIP))
				}
			} else {
				s.logger.Debug("spamtrap auto-learn: rate limited",
					slog.String("client_ip", s.clientIP))
			}
		}

		if s.backend.collector != nil {
			s.backend.collector.MessageRejected(recipientDomain, "user_unknown")
		}

		s.logger.Debug("deferred rejection: user unknown",
			slog.String("recipient", s.deferredInvalidRecipient))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "User unknown",
		}
	}

	// Local delivery (synchronous; failures reject at SMTP time).
	if len(s.recipients) > 0 {
		var deliverErr error
		now := time.Now()

		if useSessionManager {
			// Session-manager path: pass SMTP envelope fields directly.
			// Single recipient enforced by Rcpt().
			deliverErr = s.backend.smDelivery.Deliver(ctx,
				s.from, s.recipients[0], s.clientIP, s.helo, now, tmp.reader())
		} else {
			// Legacy path: build msgstore.Envelope for direct/GrpcDeliveryAgent.
			envelope := msgstore.Envelope{
				From:           s.from,
				Recipients:     s.recipients,
				ReceivedTime:   now,
				ClientIP:       net.ParseIP(s.clientIP),
				ClientHostname: s.helo,
			}
			if checkResult != nil {
				envelope.SpamResult = &msgstore.SpamResult{
					Score:   checkResult.Score,
					Action:  string(checkResult.Action),
					Checker: checkResult.CheckerName,
				}
			}
			deliverErr = deliveryAgent.Deliver(ctx, envelope, tmp.reader())
		}

		if deliverErr != nil {
			s.logger.Warn("local delivery failed",
				slog.String("from", s.from),
				slog.String("to", s.recipients[0]),
				slog.String("error", deliverErr.Error()))

			if s.backend.collector != nil {
				recipientDomain := sessionExtractRecipientDomain(s.recipients)
				s.backend.collector.MessageRejected(recipientDomain, "delivery_error")
			}

			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Delivery failed",
			}
		}

		// Notify Redis pub/sub so IMAP IDLE clients see new mail.
		folder := "INBOX"
		if checkResult != nil && checkResult.Action == spamcheck.ActionFlag {
			folder = "Junk"
		}
		for _, rcpt := range s.recipients {
			s.backend.notifier.NotifyNewMail(ctx, rcpt, folder)
		}

		if s.backend.collector != nil {
			recipientDomain := sessionExtractRecipientDomain(s.recipients)
			s.backend.collector.MessageReceived(recipientDomain, counter.n)
		}

		s.logger.Info("local delivery complete",
			slog.String("from", s.from),
			slog.String("to", s.recipients[0]),
			slog.Int64("size", counter.n))
	}

	// DMARC alignment check for outbound submission: verify the RFC 5322
	// From header domain matches the envelope sender domain. This ensures
	// DKIM signatures (applied using the envelope sender domain) will pass
	// DMARC alignment at the receiving MTA. Only checked for authenticated
	// outbound messages.
	if len(s.remoteRecipients) > 0 && s.authUser != "" && s.from != "" {
		if err := s.checkFromAlignment(tmp.reader()); err != nil {
			return err
		}
	}

	// Remote delivery: enqueue via session-manager's OutboundService.
	if len(s.remoteRecipients) > 0 {
		if s.backend.smDelivery == nil {
			s.logger.Error("remote delivery requested but no session-manager configured")
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Temporary queue failure, try again later",
			}
		}

		ctx := context.Background()
		msgID, err := s.backend.smDelivery.Enqueue(ctx, s.from, s.remoteRecipients, tmp.reader())
		if err != nil {
			s.logger.Warn("enqueue failed",
				slog.String("from", s.from),
				slog.Any("to", s.remoteRecipients),
				slog.String("error", err.Error()))

			if s.backend.collector != nil {
				recipientDomain := sessionExtractRecipientDomain(s.remoteRecipients)
				s.backend.collector.MessageRejected(recipientDomain, "queue_error")
			}

			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Temporary queue failure, try again later",
			}
		}

		if s.backend.collector != nil {
			recipientDomain := sessionExtractRecipientDomain(s.remoteRecipients)
			s.backend.collector.MessageReceived(recipientDomain, counter.n)
		}

		s.logger.Info("enqueued for remote delivery",
			slog.String("msg_id", msgID),
			slog.String("from", s.from),
			slog.Any("to", s.remoteRecipients),
			slog.Int64("size", counter.n))
	}

	return nil
}

// Reset is called when the client sends RSET.
// Implements smtp.Session interface.
func (s *Session) Reset() {
	s.from = ""
	s.mailFromSeen = false
	s.recipients = nil
	s.remoteRecipients = nil
	s.domain = nil
	s.deferredInvalidRecipient = ""
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

// sessionConnIsTLS checks whether the SMTP connection is using TLS.
// It first tries go-smtp's built-in TLS detection, then falls back to
// checking if the underlying net.Conn (possibly wrapped in notifyConn)
// is a *tls.Conn. This fallback is needed because oneConnListener wraps
// connections in notifyConn for session-end detection, which hides the
// *tls.Conn from go-smtp's direct type assertion.
func sessionConnIsTLS(c *smtp.Conn) bool {
	if _, ok := c.TLSConnectionState(); ok {
		return true
	}
	// Check if the underlying connection is TLS (wrapped by notifyConn).
	conn := c.Conn()
	if nc, ok := conn.(*notifyConn); ok {
		if _, tlsOK := nc.Conn.(*tls.Conn); tlsOK {
			return true
		}
	}
	return false
}
