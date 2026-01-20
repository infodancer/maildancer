# TODO - smtpd Implementation Status

This document tracks the implementation status of SMTP commands, extensions, and features.

## SMTP Commands (RFC 5321)

### Core Commands
- [x] HELO - RFC 5321 compliant with domain validation
- [x] EHLO - Extended HELO with capability advertisement
- [x] MAIL FROM - Sender validation with SIZE/BODY parameter parsing
- [x] RCPT TO - Recipient handling with configurable limits
- [x] DATA - Message collection with dot-stuffing per RFC 5321
- [x] RSET - Session reset (preserves HELO/auth state)
- [x] NOOP - No operation
- [x] QUIT - Clean disconnection

### Administrative Commands
- ~~VRFY~~ - Not implemented (security/privacy concern, enables address harvesting)
- ~~EXPN~~ - Not implemented (security/privacy concern, enables address harvesting)
- ~~HELP~~ - Not implemented (no practical value)

### Obsolete Commands (RFC 5321 Appendix F)
Not implemented: SEND, SOML, SAML, TURN

## SMTP Extensions

### Advertised Extensions
- [x] SIZE - Message size limits (default 25 MB, configurable)
- [x] 8BITMIME - 8-bit MIME transport
- [x] PIPELINING - Command pipelining (RFC 2920) - provided by go-smtp
- [x] CHUNKING/BDAT - Binary data transfer (RFC 3030) - provided by go-smtp
- [x] ENHANCEDSTATUSCODES - Enhanced status codes (RFC 2034) - provided by go-smtp
- [ ] DSN - Delivery Status Notifications (RFC 3461) - available via go-smtp EnableDSN

### AUTH Extension (RFC 4954)
- [x] AUTH command framework
- [x] PLAIN mechanism (RFC 4616)
- [x] TLS enforcement for PLAIN (except localhost)
- [x] Prevents username enumeration
- [x] OAUTHBEARER mechanism (RFC 7628) - JWT validation via JWKS
- ~~LOGIN~~ - Not implemented (obsolete, PLAIN is preferred)
- ~~CRAM-MD5~~ - Not implemented (MD5 broken, requires plaintext storage)
- ~~SCRAM-*~~ - Not implemented (not available in go-sasl)

### TLS Support
- [x] SMTPS (implicit TLS, port 465)
- [x] Submission with TLS (port 587)
- [x] TLS configuration (cert/key loading)
- [x] Configurable minimum TLS version (1.0-1.3)
- [x] STARTTLS command (RFC 3207)

## Anti-Spam & Filtering

### Spam Checker Integration
- [x] Generic spam checker interface (pluggable backends)
- [x] rspamd integration via HTTP API
- [ ] SpamAssassin integration via spamc

### Via rspamd (when rspamd is configured)
The following are handled by rspamd when enabled:
- [x] SPF verification (RFC 7208)
- [x] DKIM verification (RFC 6376)
- [x] DMARC policy enforcement (RFC 7489)
- [x] ARC verification (RFC 8617)
- [x] RBL/DNSBL lookups
- [x] Greylisting
- [x] Sender reputation tracking
- [x] ClamAV/antivirus integration (via rspamd antivirus module)

### Native Features (not yet implemented)
- [ ] Milter support (Sendmail milter protocol)
- [ ] Custom filter hooks

### Rate Limiting
- [ ] Per-connection rate limiting
- [ ] Per-sender rate limiting
- [ ] Per-recipient rate limiting
- [ ] Per-domain rate limiting

## Resource Management

### Limits (Implemented)
- [x] Max message size (configurable, default 25 MB)
- [x] Max recipients per message (configurable, default 100)
- [x] Email address length validation (max 320 chars)
- [x] Domain length validation (max 255 chars)

### Timeouts (Implemented)
- [x] Connection idle timeout (configurable, default 5 min)
- [x] Command timeout (configurable, default 1 min)
- [x] Idle connection monitoring with graceful cleanup

### Connection Management
- [ ] Max concurrent connections (global)
- [ ] Max connections per IP
- [ ] Connection throttling

## Observability

### Metrics (Implemented)
- [x] Prometheus metrics endpoint
- [x] Connection metrics (opened, closed, TLS)
- [x] Message metrics (received, rejected by reason)
- [x] Authentication metrics (attempts by mechanism/result)
- [x] Command processing metrics
- [x] Spam check metrics (score, result)
- [x] Delivery metrics

### Logging (Implemented)
- [x] Structured logging (slog)
- [x] Connection-scoped context
- [x] Optional transaction logging (send/recv)
- [x] Configurable log levels

## Architecture

### Plugin Interfaces (Implemented)
- [x] DeliveryAgent interface for message delivery
- [x] AuthenticationAgent interface for authentication
- [x] Metrics interface with hooks for extensions
- [x] SpamChecker interface for pluggable spam filtering

### Listener Modes (Implemented)
- [x] SMTP mode (port 25)
- [x] Submission mode (port 587)
- [x] SMTPS mode (port 465)
- [x] Alt mode (custom port)

### Configuration (Implemented)
- [x] TOML configuration format
- [x] Multi-daemon shared config support
- [x] Hot reload support (planned)

## Operational

- [x] Graceful shutdown with connection completion
- [x] Multi-listener support
- [ ] Systemd integration (socket activation)
- [ ] Docker container support
- [ ] Kubernetes deployment manifests

## Testing

- [x] Unit tests for core SMTP handlers
- [x] Auth mechanism tests
- [ ] Integration tests with real mail clients
- [ ] Load testing / benchmarks
- [ ] Fuzzing for protocol parser

## Documentation

- [x] README with basic usage
- [ ] Configuration reference
- [ ] Deployment guide
- [ ] API documentation for plugin interfaces
