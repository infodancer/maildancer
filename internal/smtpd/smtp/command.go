package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"regexp"
)

// Errors for SMTP command processing
var (
	ErrUnknownCommand    = errors.New("unknown command")
	ErrBadSequence       = errors.New("bad sequence of commands")
	ErrTooManyRecipients = errors.New("too many recipients")
	ErrInputTooLong      = errors.New("input exceeds maximum length")
)

// SessionState represents the current state of an SMTP session
type SessionState int

const (
	StateInit      SessionState = iota // Initial state, waiting for HELO/EHLO
	StateGreeted                       // After successful HELO/EHLO
	StateMailFrom                      // After successful MAIL FROM
	StateRcptTo                        // After at least one successful RCPT TO
	StateData                          // In DATA mode, receiving message content
)

// String returns a human-readable representation of the session state
func (s SessionState) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateGreeted:
		return "GREETED"
	case StateMailFrom:
		return "MAIL_FROM"
	case StateRcptTo:
		return "RCPT_TO"
	case StateData:
		return "DATA"
	default:
		return "UNKNOWN"
	}
}

// SessionConfig holds configurable limits and settings (reusable across sessions)
type SessionConfig struct {
	MaxRecipients    int   // Maximum number of RCPT TO recipients (default: 100)
	MaxMessageSize   int64 // Maximum message size in bytes (0 = unlimited)
	MaxHeloDomainLen int   // Maximum HELO/EHLO domain length (default: 255)
	MaxEmailLen      int   // Maximum email address length (default: 320)
}

// DefaultSessionConfig returns sensible defaults per RFC 5321
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxRecipients:    100,
		MaxMessageSize:   0,   // unlimited by default
		MaxHeloDomainLen: 255, // per RFC 5321
		MaxEmailLen:      320, // 64 local + @ + 255 domain
	}
}

// ConnectionInfo holds per-connection context about the client
type ConnectionInfo struct {
	ClientIP              string // Remote IP address
	ReverseDNS            string // Reverse DNS hostname (if resolved)
	ConcurrentConnections int    // Number of active connections from this IP
	Reputation            int    // Reputation score (-100 to 100, 0 = neutral)
}

// SMTPSession represents an SMTP session state
type SMTPSession struct {
	config     SessionConfig
	connInfo   ConnectionInfo
	state      SessionState
	helo       string
	sender     string
	recipients []string

	// Authentication state
	authenticated bool
	authUser      string
	authMech      string

	// TLS state
	tlsActive bool
}

// NewSMTPSession creates a new SMTP session with the given connection info and config
func NewSMTPSession(connInfo ConnectionInfo, config SessionConfig) *SMTPSession {
	return &SMTPSession{
		config:     config,
		connInfo:   connInfo,
		state:      StateInit,
		recipients: make([]string, 0),
	}
}

// Config returns the session configuration
func (s *SMTPSession) Config() SessionConfig {
	return s.config
}

// ConnInfo returns the connection information
func (s *SMTPSession) ConnInfo() ConnectionInfo {
	return s.connInfo
}

// State returns the current session state
func (s *SMTPSession) State() SessionState {
	return s.state
}

// SetState sets the session state
func (s *SMTPSession) SetState(state SessionState) {
	s.state = state
}

// SetHelo sets the HELO/EHLO domain
func (s *SMTPSession) SetHelo(domain string) {
	s.helo = domain
}

// GetHelo returns the HELO/EHLO domain
func (s *SMTPSession) GetHelo() string {
	return s.helo
}

// SetSender sets the envelope sender
func (s *SMTPSession) SetSender(sender string) {
	s.sender = sender
}

// GetSender returns the envelope sender
func (s *SMTPSession) GetSender() string {
	return s.sender
}

// AddRecipient adds a recipient to the envelope
func (s *SMTPSession) AddRecipient(recipient string) {
	s.recipients = append(s.recipients, recipient)
}

// GetRecipients returns a copy of the envelope recipients (defensive copy)
func (s *SMTPSession) GetRecipients() []string {
	result := make([]string, len(s.recipients))
	copy(result, s.recipients)
	return result
}

// RecipientCount returns the number of recipients
func (s *SMTPSession) RecipientCount() int {
	return len(s.recipients)
}

// InData returns whether the session is in DATA mode
func (s *SMTPSession) InData() bool {
	return s.state == StateData
}

// Reset resets the session state for a new transaction (keeps HELO and auth)
func (s *SMTPSession) Reset() {
	s.sender = ""
	s.recipients = make([]string, 0)
	if s.state != StateInit {
		s.state = StateGreeted
	}
}

// SetAuthenticated marks the session as authenticated with the given user and mechanism
func (s *SMTPSession) SetAuthenticated(user, mechanism string) {
	s.authenticated = true
	s.authUser = user
	s.authMech = mechanism
}

// IsAuthenticated returns whether the session is authenticated
func (s *SMTPSession) IsAuthenticated() bool {
	return s.authenticated
}

// GetAuthUser returns the authenticated username (empty if not authenticated)
func (s *SMTPSession) GetAuthUser() string {
	return s.authUser
}

// GetAuthMech returns the authentication mechanism used (empty if not authenticated)
func (s *SMTPSession) GetAuthMech() string {
	return s.authMech
}

// SetTLSActive marks the session as TLS-encrypted
func (s *SMTPSession) SetTLSActive(active bool) {
	s.tlsActive = active
}

// IsTLSActive returns whether the connection is TLS-encrypted
func (s *SMTPSession) IsTLSActive() bool {
	return s.tlsActive
}

// SMTPCommand interface defines the contract for SMTP commands using regexp patterns
type SMTPCommand interface {
	// Pattern returns the compiled regexp for matching this command
	Pattern() *regexp.Regexp

	// Execute processes the command. matches[0] is full line, matches[1:] are capture groups
	Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error)
}

// SMTPResult represents the result of processing an SMTP command
type SMTPResult struct {
	Code    int
	Message string   // Single-line message (backward compatible)
	Lines   []string // Multi-line response (optional, overrides Message if present)
}

// CommandRegistry holds registered commands and matches input against them
type CommandRegistry struct {
	commands []SMTPCommand
}

// NewCommandRegistry creates a new command registry with all standard SMTP commands.
// tlsConfig is optional and enables STARTTLS support when provided.
func NewCommandRegistry(hostname string, authAgent interface{}, tlsConfig *tls.Config) *CommandRegistry {
	commands := []SMTPCommand{
		&EHLOCommand{hostname: hostname, authAgent: authAgent, tlsConfig: tlsConfig},
		&HELOCommand{},
		&MAILCommand{},
		&RCPTCommand{},
		&DATACommand{},
		&RSETCommand{},
		&NOOPCommand{},
		&QUITCommand{},
	}

	// Add STARTTLS command if TLS configuration is available
	if tlsConfig != nil {
		commands = append([]SMTPCommand{&STARTTLSCommand{tlsConfig: tlsConfig}}, commands...)
	}

	// Add AUTH command if authentication agent is configured
	if authAgent != nil {
		commands = append([]SMTPCommand{&AUTHCommand{authAgent: authAgent}}, commands...)
	}

	return &CommandRegistry{
		commands: commands,
	}
}

// Match finds the command that matches the input line and returns it with captured groups
func (r *CommandRegistry) Match(line string) (SMTPCommand, []string, error) {
	for _, cmd := range r.commands {
		if matches := cmd.Pattern().FindStringSubmatch(line); matches != nil {
			return cmd, matches, nil
		}
	}
	return nil, nil, ErrUnknownCommand
}

// Pre-compiled regexp patterns for SMTP commands
var (
	ehloPattern = regexp.MustCompile(`(?i)^EHLO\s+(\S+)\s*$`)
	heloPattern = regexp.MustCompile(`(?i)^HELO\s+(\S+)\s*$`)
	mailPattern = regexp.MustCompile(`(?i)^MAIL\s+FROM:\s*<([^>]*)>(.*)$`)
	rcptPattern = regexp.MustCompile(`(?i)^RCPT\s+TO:\s*<([^>]*)>(.*)$`)
	dataPattern = regexp.MustCompile(`(?i)^DATA\s*$`)
	rsetPattern = regexp.MustCompile(`(?i)^RSET\s*$`)
	noopPattern = regexp.MustCompile(`(?i)^NOOP(?:\s.*)?$`)
	quitPattern = regexp.MustCompile(`(?i)^QUIT\s*$`)
)

// EHLOCommand implements the EHLO command
type EHLOCommand struct {
	hostname  string
	authAgent interface{}  // auth.AuthenticationAgent (using interface{} to avoid import cycle)
	tlsConfig *tls.Config  // TLS configuration for STARTTLS support
}

func (c *EHLOCommand) Pattern() *regexp.Regexp {
	return ehloPattern
}

func (c *EHLOCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	domain := matches[1]

	// Validate domain length
	if len(domain) > session.Config().MaxHeloDomainLen {
		return SMTPResult{Code: 501, Message: "Domain name too long"}, nil
	}

	session.SetHelo(domain)
	session.SetState(StateGreeted)

	clientIP := session.ConnInfo().ClientIP
	if clientIP == "" {
		clientIP = "unknown"
	}

	// Build multi-line response with capabilities
	hostname := c.hostname
	if hostname == "" {
		hostname = "localhost"
	}

	lines := []string{
		hostname + " Hello " + domain + " [" + clientIP + "]",
		"SIZE 26214400",
		"8BITMIME",
	}

	// Advertise STARTTLS if TLS config is available and TLS is not already active
	if c.tlsConfig != nil && !session.IsTLSActive() {
		lines = append(lines, "STARTTLS")
	}

	// Add AUTH capability if auth agent is configured and conditions are met
	if c.authAgent != nil {
		// Only advertise AUTH if TLS is active or connection is from localhost
		if session.IsTLSActive() || isLocalhost(clientIP) {
			lines = append(lines, "AUTH PLAIN LOGIN")
		}
	}

	return SMTPResult{Code: 250, Lines: lines}, nil
}

// HELOCommand implements the HELO command
type HELOCommand struct{}

func (c *HELOCommand) Pattern() *regexp.Regexp {
	return heloPattern
}

func (c *HELOCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	domain := matches[1]

	// Validate domain length
	if len(domain) > session.Config().MaxHeloDomainLen {
		return SMTPResult{Code: 501, Message: "Domain name too long"}, nil
	}

	session.SetHelo(domain)
	session.SetState(StateGreeted)

	clientIP := session.ConnInfo().ClientIP
	if clientIP == "" {
		clientIP = "unknown"
	}

	return SMTPResult{Code: 250, Message: "Hello " + domain + " [" + clientIP + "]"}, nil
}

// MAILCommand implements the MAIL command
type MAILCommand struct{}

func (c *MAILCommand) Pattern() *regexp.Regexp {
	return mailPattern
}

func (c *MAILCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	// Check state - must be greeted first
	if session.State() < StateGreeted {
		return SMTPResult{Code: 503, Message: "Bad sequence of commands"}, nil
	}

	email := matches[1]
	// matches[2] contains optional parameters (SIZE, BODY, etc.) - ignored for now

	// Validate email length
	if len(email) > session.Config().MaxEmailLen {
		return SMTPResult{Code: 501, Message: "Email address too long"}, nil
	}

	// Reset any previous transaction and set new sender
	session.Reset()
	session.SetSender(email)
	session.SetState(StateMailFrom)

	return SMTPResult{Code: 250, Message: "OK"}, nil
}

// RCPTCommand implements the RCPT command
type RCPTCommand struct{}

func (c *RCPTCommand) Pattern() *regexp.Regexp {
	return rcptPattern
}

func (c *RCPTCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	// Check state - must have MAIL FROM first
	if session.State() < StateMailFrom {
		return SMTPResult{Code: 503, Message: "Bad sequence of commands"}, nil
	}

	email := matches[1]
	// matches[2] contains optional parameters - ignored for now

	// Validate email length
	if len(email) > session.Config().MaxEmailLen {
		return SMTPResult{Code: 501, Message: "Email address too long"}, nil
	}

	// Check recipient limit
	if session.RecipientCount() >= session.Config().MaxRecipients {
		return SMTPResult{Code: 452, Message: "Too many recipients"}, nil
	}

	session.AddRecipient(email)
	session.SetState(StateRcptTo)

	return SMTPResult{Code: 250, Message: "OK"}, nil
}

// DATACommand implements the DATA command
type DATACommand struct{}

func (c *DATACommand) Pattern() *regexp.Regexp {
	return dataPattern
}

func (c *DATACommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	// Check state - must have at least one recipient
	if session.State() < StateRcptTo {
		return SMTPResult{Code: 503, Message: "Bad sequence of commands"}, nil
	}

	session.SetState(StateData)

	return SMTPResult{Code: 354, Message: "Start mail input; end with <CRLF>.<CRLF>"}, nil
}

// RSETCommand implements the RSET command
type RSETCommand struct{}

func (c *RSETCommand) Pattern() *regexp.Regexp {
	return rsetPattern
}

func (c *RSETCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	session.Reset()
	return SMTPResult{Code: 250, Message: "OK"}, nil
}

// NOOPCommand implements the NOOP command
type NOOPCommand struct{}

func (c *NOOPCommand) Pattern() *regexp.Regexp {
	return noopPattern
}

func (c *NOOPCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	return SMTPResult{Code: 250, Message: "OK"}, nil
}

// QUITCommand implements the QUIT command
type QUITCommand struct{}

func (c *QUITCommand) Pattern() *regexp.Regexp {
	return quitPattern
}

func (c *QUITCommand) Execute(ctx context.Context, session *SMTPSession, matches []string) (SMTPResult, error) {
	return SMTPResult{Code: 221, Message: "Goodbye"}, nil
}

// isLocalhost checks if the given IP address is a localhost address
func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" ||
		len(ip) > 4 && ip[:4] == "127." || ip == "localhost"
}
