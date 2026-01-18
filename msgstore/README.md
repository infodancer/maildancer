# msgstore

Message storage library for the infodancer mail server suite. Provides a centralized storage layer used by smtpd, pop3d, and imapd.

## Architecture

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│  smtpd  │     │  pop3d  │     │  imapd  │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │ DeliveryAgent │ MessageStore  │ MessageStore
     │ AuthProvider  │ AuthProvider  │ AuthProvider
     │               │               │
     └───────────────┴───────────────┘
                     │
              ┌──────┴──────┐
              │  msgstore   │
              └─────────────┘
```

## Interfaces

### DeliveryAgent

Used by smtpd to deliver accepted messages to storage after filtering.

```go
type DeliveryAgent interface {
    Deliver(ctx context.Context, envelope Envelope, message io.Reader) error
}
```

### AuthProvider

Shared authentication interface for all mail daemons.

```go
type AuthProvider interface {
    Authenticate(ctx context.Context, username, password string) (*User, error)
}
```

### MessageStore

Read-access interface for pop3d and imapd to retrieve messages.

```go
type MessageStore interface {
    List(ctx context.Context, mailbox string) ([]MessageInfo, error)
    Retrieve(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error)
    Delete(ctx context.Context, mailbox string, uid string) error
    Expunge(ctx context.Context, mailbox string) error
    Stat(ctx context.Context, mailbox string) (count int, totalBytes int64, err error)
}
```

## Planned Storage Backends

- Maildir (initial implementation)
- Database-backed storage (future)

## Related Projects

- [smtpd](https://github.com/infodancer/smtpd) - SMTP daemon
- [pop3d](https://github.com/infodancer/pop3d) - POP3 daemon
- [imapd](https://github.com/infodancer/imapd) - IMAP daemon

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
