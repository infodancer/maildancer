# smtpd

A production-ready, high-performance SMTP server written in idiomatic Go.

## Overview

`smtpd` is a modern SMTP server implementation focused exclusively on receiving mail via the SMTP protocol. It is designed to be:

- **Production-ready** - Battle-tested with comprehensive error handling, graceful shutdown, and operational observability
- **High-performance** - Efficient concurrent connection handling with minimal allocations
- **Modular** - Clean interfaces allow plugging in custom authentication, filtering, and delivery backends
- **Embeddable** - Use as a standalone daemon or embed the library in your own applications

This module is part of a mail server suite alongside [pop3d](https://github.com/infodancer/maildancer/internal/pop3d), [imapd](https://github.com/infodancer/maildancer/internal/imapd), and [messagestore](https://github.com/infodancer/messagestore). The `smtpd` handles SMTP protocol concerns only; message storage and delivery are delegated to the `messagestore` module via well-defined interfaces.

## Design Philosophy

**Reject early, never bounce.** The smtpd validates all messages during the SMTP conversation and rejects invalid mail with appropriate 5xx response codes before accepting. Once a message is accepted (250 response to DATA), it is handed off to the delivery agent. The smtpd never generates bounce messages - if a bounce is needed after acceptance, that responsibility belongs to the messagestore.

This design:
- Reduces backscatter spam (bounces to forged addresses)
- Provides immediate feedback to legitimate senders
- Keeps the smtpd focused on protocol handling
- Simplifies error handling and message flow

## Features

### Core Protocol
- [ ] RFC 5321 compliant SMTP server
- [ ] EHLO/HELO with capability advertisement
- [ ] MAIL FROM / RCPT TO / DATA command handling
- [ ] Proper response codes and enhanced status codes (RFC 2034/3463)
- [ ] Connection timeouts and resource limits
- [ ] Graceful shutdown with in-flight message completion

### Security & Encryption
- [ ] STARTTLS support (RFC 3207)
- [ ] Configurable TLS (versions, cipher suites, certificates)
- [ ] AUTH extension (RFC 4954)
  - [ ] PLAIN mechanism
  - [ ] LOGIN mechanism
  - [ ] CRAM-MD5 mechanism

### SMTP Extensions
- [ ] SIZE - Message size declaration (RFC 1870)
- [ ] 8BITMIME - 8-bit MIME transport (RFC 6152)
- [ ] PIPELINING - Command pipelining (RFC 2920)

### Anti-Spam & Filtering
- [ ] SPF verification (RFC 7208)
- [ ] DKIM verification (RFC 6376)
- [ ] DMARC policy enforcement (RFC 7489)
- [ ] RBL/DNSBL lookups
- [ ] Milter protocol support (Sendmail mail filter API)
- [ ] SpamAssassin integration via spamc
- [ ] Rate limiting (per IP, per sender, per recipient domain)
- [ ] Greylisting support

### Operational
- [ ] Structured logging (slog)
- [ ] Metrics export (Prometheus-compatible)
- [ ] Configuration via YAML/TOML and environment variables
- [ ] Hot configuration reload (SIGHUP)

## RFC Compliance

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321) | Simple Mail Transfer Protocol | Planned |
| [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322) | Internet Message Format | Planned |
| [RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123) | Requirements for Internet Hosts | Planned |
| [RFC 4954](https://datatracker.ietf.org/doc/html/rfc4954) | SMTP Service Extension for Authentication | Planned |
| [RFC 3207](https://datatracker.ietf.org/doc/html/rfc3207) | SMTP Service Extension for Secure SMTP over TLS | Planned |
| [RFC 1870](https://datatracker.ietf.org/doc/html/rfc1870) | SMTP Service Extension for Message Size Declaration | Planned |
| [RFC 6152](https://datatracker.ietf.org/doc/html/rfc6152) | SMTP Service Extension for 8-bit MIME Transport | Planned |
| [RFC 2920](https://datatracker.ietf.org/doc/html/rfc2920) | SMTP Service Extension for Command Pipelining | Planned |
| [RFC 2034](https://datatracker.ietf.org/doc/html/rfc2034) | SMTP Service Extension for Returning Enhanced Error Codes | Planned |
| [RFC 3463](https://datatracker.ietf.org/doc/html/rfc3463) | Enhanced Mail System Status Codes | Planned |
| [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) | Sender Policy Framework (SPF) | Planned |
| [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376) | DomainKeys Identified Mail (DKIM) Signatures | Planned |
| [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) | Domain-based Message Authentication (DMARC) | Planned |

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
│                  │    Auth     │       │   Delivery   │─────────┼──▶ messagestore
│                  │  Provider   │       │    Agent     │         │
│                  │ (interface) │       │  (interface) │         │
│                  └─────────────┘       └──────────────┘         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Interfaces

**DeliveryAgent** - Receives accepted messages after filtering. Implementations handle local mailbox delivery or queue for relay. The `messagestore` module provides the reference implementation.

**AuthProvider** - Validates user credentials during SMTP AUTH. Can integrate with various backends (database, LDAP, PAM, etc.).

**Filter** - Pluggable message inspection. Built-in filters for SPF, DKIM, DMARC, RBL. External integration via Milter protocol and spamc.

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
smtpd -config /etc/smtpd/config.yaml
```

### Embedded

```go
package main

import (
    "github.com/infodancer/maildancer/internal/smtpd"
    "github.com/infodancer/messagestore"
)

func main() {
    store := messagestore.New(...)

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
- [messagestore](https://github.com/infodancer/messagestore) - Message storage backend

## Development

See [CONVENTIONS.md](CONVENTIONS.md) for Go coding standards.

### Prerequisites

- Go 1.23+
- Task runner (`go install github.com/go-task/task/v3/cmd/task@latest`)

### Commands

```bash
task build      # Build the binary
task test       # Run tests
task lint       # Run linter
task vulncheck  # Check for vulnerabilities
task all        # Run all checks
```
