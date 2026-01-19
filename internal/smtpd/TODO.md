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
- [ ] VRFY - Verify user address
- [ ] EXPN - Expand mailing list
- [ ] HELP - Help information

### Obsolete Commands (RFC 5321 Appendix F)
- [ ] SEND - Not planned
- [ ] SOML - Not planned
- [ ] SAML - Not planned
- [ ] TURN - Not planned

## SMTP Extensions

### Advertised Extensions
- [x] SIZE - Message size limits (default 25 MB, configurable)
- [x] 8BITMIME - 8-bit MIME transport
- [ ] PIPELINING - Command pipelining (RFC 2920)
- [ ] CHUNKING/BDAT - Binary data transfer (RFC 3030)
- [ ] DSN - Delivery Status Notifications (RFC 3461)
- [ ] ENHANCEDSTATUSCODES - Enhanced status codes (RFC 2034)

### AUTH Extension (RFC 4954)
- [x] AUTH command framework
- [x] PLAIN mechanism (RFC 4616)
- [ ] LOGIN mechanism
- [ ] CRAM-MD5 mechanism
- [ ] SCRAM-SHA-1 mechanism
- [ ] SCRAM-SHA-256 mechanism
- [x] TLS enforcement for PLAIN (except localhost)
- [x] Prevents username enumeration

### TLS Support
- [x] SMTPS (implicit TLS, port 465)
- [x] Submission with TLS (port 587)
- [x] TLS configuration (cert/key loading)
- [x] Configurable minimum TLS version (1.0-1.3)
- [ ] STARTTLS command (RFC 3207) - infrastructure ready

## Anti-Spam & Filtering

### Email Authentication
- [ ] SPF verification (RFC 7208)
- [ ] DKIM verification (RFC 6376)
- [ ] DMARC policy enforcement (RFC 7489)
- [ ] ARC verification (RFC 8617)

### Reputation Systems
- [ ] RBL/DNSBL lookups
- [ ] Greylisting
- [ ] Sender reputation tracking

### Content Filtering
- [ ] Milter support (Sendmail milter protocol)
- [ ] SpamAssassin integration via spamc
- [ ] ClamAV integration via clamd
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
- [x] Anti-spam metric hooks (SPF, DKIM, DMARC, RBL)
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
