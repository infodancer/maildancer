# pop3d

A POP3 server implementation in idiomatic Go, focused solely on the POP3 protocol with SSL/TLS support. Message storage and authentication are delegated to external modules via interfaces.

## Relevant RFCs

| RFC | Title | Description |
|-----|-------|-------------|
| [RFC 1939](https://datatracker.ietf.org/doc/html/rfc1939) | Post Office Protocol - Version 3 | Core POP3 specification defining commands, states, and responses |
| [RFC 2449](https://datatracker.ietf.org/doc/html/rfc2449) | POP3 Extension Mechanism | CAPA command and extension framework (TOP, UIDL, etc.) |
| [RFC 2595](https://datatracker.ietf.org/doc/html/rfc2595) | Using TLS with IMAP, POP3 and ACAP | STARTTLS extension for upgrading connections |
| [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) | Cleartext Considered Obsolete | Implicit TLS on port 995, modern security requirements |
| [RFC 5034](https://datatracker.ietf.org/doc/html/rfc5034) | POP3 SASL Authentication | SASL authentication mechanism for POP3 |
| [RFC 1734](https://datatracker.ietf.org/doc/html/rfc1734) | POP3 AUTHentication command | Original AUTH command (superseded by RFC 5034) |

## Intended Features

### Core POP3 Commands (RFC 1939)

**AUTHORIZATION State:**
- `USER` - Specify username
- `PASS` - Specify password
- `APOP` - APOP authentication (MD5-based challenge-response)
- `QUIT` - End session

**TRANSACTION State:**
- `STAT` - Get mailbox status (message count and size)
- `LIST` - List message sizes
- `RETR` - Retrieve a message
- `DELE` - Mark message for deletion
- `NOOP` - No operation (keep-alive)
- `RSET` - Reset deletion marks

**UPDATE State:**
- `QUIT` - Commit deletions and close connection

### Extensions (RFC 2449)

- `CAPA` - Capability advertisement
- `TOP` - Retrieve message headers plus n lines of body
- `UIDL` - Unique-ID listing for message tracking

### Security

- **Implicit TLS** (port 995) - Direct TLS connection per RFC 8314
- **STARTTLS** (port 110) - Upgrade plaintext to TLS per RFC 2595
- **SASL Authentication** - Extensible authentication framework per RFC 5034

## Architecture

### Scope Boundaries

This module is responsible for:
- POP3 protocol parsing and response generation
- Connection state management (AUTHORIZATION, TRANSACTION, UPDATE)
- TLS/SSL handling (both implicit and STARTTLS)
- Session management

This module delegates to external interfaces:
- **Message Storage** - Retrieving, listing, and deleting messages
- **Authentication** - Validating user credentials

### Interface Design

```go
// Mailbox provides access to a user's messages
type Mailbox interface {
    // Stat returns the number of messages and total size in octets
    Stat() (count int, size int64, err error)

    // List returns the size of message n (1-indexed), or all messages if n is 0
    List(n int) ([]MessageInfo, error)

    // Retr retrieves the full message content
    Retr(n int) (io.ReadCloser, error)

    // Dele marks a message for deletion
    Dele(n int) error

    // Rset unmarks all messages marked for deletion
    Rset() error

    // Top retrieves headers plus n lines of body
    Top(msg int, lines int) (io.ReadCloser, error)

    // Uidl returns unique IDs for messages
    Uidl(n int) ([]UidlInfo, error)

    // Commit finalizes deletions (called on QUIT from TRANSACTION state)
    Commit() error

    // Close releases resources without committing
    Close() error
}

// Authenticator validates user credentials and returns a Mailbox
type Authenticator interface {
    // Authenticate validates credentials and returns a mailbox on success
    Authenticate(username, password string) (Mailbox, error)

    // AuthenticateAPOP validates APOP credentials (username, digest, timestamp)
    AuthenticateAPOP(username, digest, timestamp string) (Mailbox, error)
}
```

## Prerequisites

- [Go](https://go.dev/) 1.23 or later
- [Task](https://taskfile.dev/) - A task runner / simpler Make alternative
- [golangci-lint](https://golangci-lint.run/) - Go linters aggregator
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability checker

### Installing Dependencies

Install Task following the [installation instructions](https://taskfile.dev/installation/).

Install Go development tools:

```bash
task install:deps
```

## Development

### Available Tasks

Run `task --list` to see all available tasks:

| Task | Description |
|------|-------------|
| `task build` | Build the Go binary |
| `task lint` | Run golangci-lint |
| `task vulncheck` | Run govulncheck for security vulnerabilities |
| `task test` | Run tests |
| `task test:coverage` | Run tests with coverage report |
| `task all` | Run all checks (build, lint, vulncheck, test) |
| `task clean` | Clean build artifacts |
| `task install:deps` | Install development dependencies |
| `task hooks:install` | Configure git to use project hooks |

### Git Hooks

This project includes a pre-push hook that runs all checks before pushing. To enable it:

```bash
task hooks:install
```

This configures git to use the `.githooks` directory for hooks.

## License

See [LICENSE](LICENSE) for details.
