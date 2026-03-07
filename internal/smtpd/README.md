# smtpd

A production-ready, high-performance SMTP server written in idiomatic Go.

## Overview

`smtpd` is a modern SMTP server implementation focused exclusively on receiving mail via the SMTP protocol. It is designed to be:

- **Production-ready** - Battle-tested with comprehensive error handling, graceful shutdown, and operational observability
- **High-performance** - Efficient concurrent connection handling with minimal allocations
- **Modular** - Clean interfaces allow plugging in custom authentication, filtering, and delivery backends
- **Embeddable** - Use as a standalone daemon or embed the library in your own applications

This module is part of a mail server suite alongside [pop3d](https://github.com/infodancer/maildancer/internal/pop3d), [imapd](https://github.com/infodancer/maildancer/internal/imapd), and [msgstore](https://github.com/infodancer/maildancer/msgstore). The `smtpd` handles SMTP protocol concerns only; message storage and delivery are delegated to the `msgstore` module via well-defined interfaces.

## Design Philosophy

**Reject early, never bounce.** The smtpd validates messages during the SMTP conversation and rejects invalid mail with appropriate response codes. Validation occurs at multiple stages:

1. **Connection phase** - IP-based checks (RBL, rate limits)
2. **MAIL FROM** - Sender validation (SPF, domain checks)
3. **RCPT TO** - Recipient validation (local user verification)
4. **DATA content** - Message inspection (DKIM, DMARC, content filtering)

After the client sends message content, the smtpd passes the message to the DeliveryAgent. The final response to the client reflects the DeliveryAgent's status:
- `250` - Message accepted for delivery
- `4xx` - Temporary failure (client should retry)
- `5xx` - Permanent failure (message rejected)

The smtpd never generates bounce messages after the SMTP conversation ends. All success, temporary failure, and permanent failure conditions are reported synchronously to the sending MTA.

This design:
- Reduces backscatter spam (no bounces to forged addresses)
- Provides immediate feedback to legitimate senders
- Ensures delivery failures are reported synchronously
- Keeps the smtpd focused on protocol handling

## Features

### Core Protocol
- [x] RFC 5321 compliant SMTP server
- [x] EHLO/HELO with capability advertisement
- [x] MAIL FROM / RCPT TO / DATA command handling
- [x] Proper response codes and enhanced status codes (RFC 2034/3463)
- [x] Connection timeouts and resource limits
- [x] Graceful shutdown with in-flight message completion

### Security & Encryption
- [x] STARTTLS support (RFC 3207)
- [x] Configurable TLS (versions, cipher suites, certificates)
- [x] AUTH extension (RFC 4954)
  - [x] PLAIN mechanism
  - [x] OAUTHBEARER mechanism (JWT via JWKS)

### SMTP Extensions
- [x] SIZE - Message size declaration and enforcement (RFC 1870)
- [x] 8BITMIME - 8-bit MIME transport (RFC 6152)
- [x] PIPELINING - Command pipelining (RFC 2920)
- [x] CHUNKING/BDAT - Binary data transfer (RFC 3030)
- [x] ENHANCEDSTATUSCODES (RFC 2034)

### Anti-Spam & Filtering
- [x] SPF verification (via rspamd)
- [x] DKIM verification (via rspamd)
- [x] DMARC policy enforcement (via rspamd)
- [x] RBL/DNSBL lookups (via rspamd)
- [x] Greylisting (via rspamd)
- [ ] Milter protocol support (Sendmail mail filter API)
- [ ] SpamAssassin integration via spamc

### Operational
- [x] Structured logging (slog)
- [x] Metrics export (Prometheus-compatible)
- [x] Configuration via TOML and environment variables

## RFC Compliance

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321) | Simple Mail Transfer Protocol | Implemented |
| [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322) | Internet Message Format | Implemented |
| [RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123) | Requirements for Internet Hosts | Implemented |
| [RFC 4954](https://datatracker.ietf.org/doc/html/rfc4954) | SMTP Service Extension for Authentication | Implemented |
| [RFC 3207](https://datatracker.ietf.org/doc/html/rfc3207) | SMTP Service Extension for Secure SMTP over TLS | Implemented |
| [RFC 1870](https://datatracker.ietf.org/doc/html/rfc1870) | SMTP Service Extension for Message Size Declaration | Implemented |
| [RFC 6152](https://datatracker.ietf.org/doc/html/rfc6152) | SMTP Service Extension for 8-bit MIME Transport | Implemented |
| [RFC 2920](https://datatracker.ietf.org/doc/html/rfc2920) | SMTP Service Extension for Command Pipelining | Implemented |
| [RFC 3030](https://datatracker.ietf.org/doc/html/rfc3030) | SMTP Service Extensions for Transmission of Large and Binary MIME Messages | Implemented |
| [RFC 2034](https://datatracker.ietf.org/doc/html/rfc2034) | SMTP Service Extension for Returning Enhanced Error Codes | Implemented |
| [RFC 3463](https://datatracker.ietf.org/doc/html/rfc3463) | Enhanced Mail System Status Codes | Implemented |
| [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) | Sender Policy Framework (SPF) | Via rspamd |
| [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376) | DomainKeys Identified Mail (DKIM) Signatures | Via rspamd |
| [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) | Domain-based Message Authentication (DMARC) | Via rspamd |
| [RFC 6409](https://datatracker.ietf.org/doc/html/rfc6409) | Message Submission for Mail | Implemented |
| [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) | Cleartext Considered Obsolete: Use of TLS for Email | Implemented |

## Architecture

```
                              smtpd
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────────────┐    │
│  │ Listener │───▶│   Session   │───▶│    Filter Chain      │    │
│  │  (TLS)   │    │   Handler   │    │ (SPF/DKIM/RBL/Milter)│    │
│  └──────────┘    └─────────────┘    └──────────────────────┘    │
│                         │                      │                 │
│                         ▼                      ▼                 │
│                  ┌─────────────┐       ┌──────────────┐         │
│                  │    Auth     │       │   Delivery   │─────────┼──▶ msgstore
│                  │  Provider   │       │    Agent     │         │
│                  │ (interface) │       │  (interface) │         │
│                  └─────────────┘       └──────────────┘         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Interfaces

**DeliveryAgent** - Receives accepted messages after filtering. Implementations handle local mailbox delivery or queue for relay. The `msgstore` module provides the reference implementation.

**AuthProvider** - Validates user credentials during SMTP AUTH. Can integrate with various backends (database, LDAP, PAM, etc.).

**Filter** - Pluggable message inspection. Built-in filters for SPF, DKIM, DMARC, RBL. External integration via Milter protocol and spamc.

## Deployment

The smtpd can be deployed in two modes:

- **Standalone** - Run directly as a system daemon, managed by systemd or similar
- **Docker** - Run within a container, suitable for orchestrated environments

## Configuration

Configuration uses TOML format with section support, allowing a single configuration file to be shared across the mail server suite (smtpd, pop3d, imapd, msgstore).

```toml
[smtpd]
hostname = "mail.example.com"
max_message_size = 26214400  # 25 MB
max_recipients = 100

[smtpd.listeners]
  [smtpd.listeners.smtp]
  address = ":25"
  mode = "smtp"

  [smtpd.listeners.submission]
  address = ":587"
  mode = "submission"

  [smtpd.listeners.smtps]
  address = ":465"
  mode = "smtps"

[smtpd.tls]
cert_file = "/etc/smtpd/certs/mail.crt"
key_file = "/etc/smtpd/certs/mail.key"
min_version = "TLS1.2"

[pop3d]
# pop3d-specific settings (separate daemon)

[imapd]
# imapd-specific settings (separate daemon)

[msgstore]
# shared message storage settings
```

## Listening Modes

The smtpd supports multiple listening modes with different security and authentication requirements:

| Port | Mode | TLS | AUTH | Description |
|------|------|-----|------|-------------|
| 25 | SMTP | STARTTLS optional | Optional | MTA-to-MTA mail transfer |
| 465 | SMTPS | Implicit TLS | Required | Secure submission (RFC 8314) |
| 587 | Submission | STARTTLS required | Required | Mail submission from MUAs (RFC 6409) |
| 2525 | Alt SMTP | STARTTLS optional | Optional | Alternative for blocked port 25 |

### Mode Behaviors

**SMTP (Port 25)**
- Accepts mail from other mail servers
- STARTTLS offered but not required
- AUTH typically not required for delivery to local domains
- Full anti-spam filtering (SPF, DKIM, DMARC, RBL)

**Submission (Port 587)**
- For authenticated users submitting outbound mail
- STARTTLS required before AUTH (per RFC 6409)
- AUTH required for all operations
- Reduced anti-spam checks for authenticated users

**SMTPS (Port 465)**
- Implicit TLS - TLS handshake occurs immediately upon connection
- Behaves like submission mode after TLS established
- Reinstated as standard by RFC 8314

## Observability

The smtpd exposes metrics via Prometheus. A metrics endpoint is available for scraping by Prometheus or compatible collectors.

### Metrics Endpoint

```toml
[smtpd.metrics]
enabled = true
address = ":9100"
path = "/metrics"
```

### Fetching Metrics Manually

Metrics can be fetched directly with curl for debugging or monitoring without Prometheus:

```bash
# Fetch all metrics
curl http://localhost:9100/metrics

# Silent mode (no progress bar)
curl -s http://localhost:9100/metrics

# Filter specific metrics
curl -s http://localhost:9100/metrics | grep smtpd_connections

# Watch metrics in real-time (every 2 seconds)
watch -n2 'curl -s http://localhost:9100/metrics | grep smtpd_connections'
```

### Available Metrics

**Connection Metrics**
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `smtpd_connections_total` | Counter | `listener`, `ip` | Total connections by source IP |
| `smtpd_connections_active` | Gauge | `listener` | Currently active connections |
| `smtpd_tls_connections_total` | Counter | `listener`, `version` | TLS connections by protocol version |

**Message Metrics**
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `smtpd_messages_received_total` | Counter | `listener`, `recipient_domain` | Messages received by recipient domain |
| `smtpd_messages_rejected_total` | Counter | `listener`, `reason`, `recipient_domain` | Messages rejected by reason and domain |
| `smtpd_messages_size_bytes` | Histogram | `listener` | Message size distribution |

**Authentication Metrics**
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `smtpd_auth_attempts_total` | Counter | `listener`, `mechanism`, `result` | Auth attempts by mechanism and result |

**Anti-Spam Metrics**
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `smtpd_spf_checks_total` | Counter | `result` | SPF check results (pass, fail, softfail, none) |
| `smtpd_dkim_checks_total` | Counter | `result` | DKIM verification results |
| `smtpd_dmarc_checks_total` | Counter | `result` | DMARC policy check results |
| `smtpd_rbl_hits_total` | Counter | `list` | RBL/DNSBL hits by blocklist |
| `smtpd_spam_score` | Histogram | `recipient_domain` | Spam score distribution by recipient domain |
| `smtpd_spam_rejected_total` | Counter | `recipient_domain` | Messages rejected as spam by recipient domain |

**Performance Metrics**
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `smtpd_command_duration_seconds` | Histogram | `command` | Command processing time |
| `smtpd_delivery_duration_seconds` | Histogram | `result` | DeliveryAgent processing time |

### Privacy Considerations

Metrics are aggregated by **recipient domain** rather than individual recipient addresses to respect user privacy. Source IPs are tracked for connection metrics to support operational security monitoring (identifying abusive sources), but message-level metrics do not include sender-identifying information.

## Installation

### Standalone Server

```bash
go install github.com/infodancer/maildancer/internal/smtpd/cmd/smtpd@latest
```

### As Library

```bash
go get github.com/infodancer/maildancer/internal/smtpd
```

## Usage

### Standalone

```bash
smtpd -config /etc/smtpd/config.toml
```

### Embedded

```go
package main

import (
    "github.com/infodancer/maildancer/internal/smtpd"
    "github.com/infodancer/maildancer/msgstore"
)

func main() {
    store := msgstore.New(...)

    server := smtpd.New(
        smtpd.WithAddress(":25"),
        smtpd.WithTLS(certFile, keyFile),
        smtpd.WithDeliveryAgent(store),
        smtpd.WithAuth(myAuthProvider),
    )

    server.ListenAndServe()
}
```

## Related Projects

- [pop3d](https://github.com/infodancer/maildancer/internal/pop3d) - POP3 server
- [imapd](https://github.com/infodancer/maildancer/internal/imapd) - IMAP server
- [msgstore](https://github.com/infodancer/maildancer/msgstore) - Message storage backend

## Development

See [CONVENTIONS.md](CONVENTIONS.md) for Go coding standards.

### Prerequisites

- Go 1.25+
- Task runner (`go install github.com/go-task/task/v3/cmd/task@latest`)

### Commands

```bash
task build      # Build the binary
task test       # Run tests
task lint       # Run linter
task vulncheck  # Check for vulnerabilities
task all        # Run all checks
```
