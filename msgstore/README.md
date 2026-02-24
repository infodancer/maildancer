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

- Maildir (current implementation)
- Database-backed storage (future)

## Planned Features

### End-to-End Encryption

The intended design treats msgstore as a pure blob store — **msgstore never sees decrypted data**. Encryption and decryption are the responsibility of the protocol daemons, using the recipient's keys from the `auth` module.

Intended security boundaries:

| Component | Responsibility |
|-----------|---------------|
| smtpd | Encrypts messages using recipient's public key before delivery |
| msgstore | Stores and retrieves encrypted blobs only |
| pop3d | Decrypts messages using user's private key after retrieval |
| automation | Connects as a client with its own keypair |

Intended data flow:

```
┌────────────────────────────────────────────────────────────────┐
│                         DELIVERY                               │
│  [plaintext] → smtpd encrypts → DeliveryAgent → msgstore       │
│                                                  (ciphertext)  │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                         RETRIEVAL                              │
│  msgstore → MessageStore.Retrieve() → pop3d decrypts → [plain] │
│  (ciphertext)                                                  │
└────────────────────────────────────────────────────────────────┘
```

The planned algorithm is X25519 key exchange with XSalsa20-Poly1305 authenticated encryption (NaCl/libsodium box). The `Envelope.Encryption` field is reserved for this metadata:

```go
type EncryptionInfo struct {
    Algorithm string  // e.g., "x25519-xsalsa20-poly1305"
    Encrypted bool
}
```

Note: IMAP SEARCH/SORT require plaintext access and are incompatible with encrypted storage; IMAP support will require a separate design.

### Sieve Filtering

Sieve script evaluation (RFC 5228) is planned for per-user mail filtering rules. The current implementation parses Sieve scripts but does not evaluate them; delivery falls through to default routing. Full evaluation support is a future milestone.

## Concurrency

### Delivery

Concurrent delivery to the same mailbox from multiple goroutines or processes is safe. The Maildir format guarantees atomicity through unique filename generation and atomic filesystem rename; no additional locking is required at the msgstore layer.

### Retrieval and Deletion

Soft-delete state (marking messages for deletion before `Expunge`) is tracked in memory and protected by a per-`MaildirStore` mutex. This state is **not shared across instances** — each `MaildirStore` opened independently (e.g., in separate processes) maintains its own deletion tracking. Protocol-level locking (such as POP3's exclusive mailbox lock during a session) is the responsibility of the daemon, not msgstore.

`Expunge` permanently removes deleted messages from disk and is safe to call from a single goroutine within a session. Concurrent `Expunge` calls across sessions against the same mailbox are not recommended without external coordination.

## Observability

Prometheus metrics support for monitoring, aggregated at the domain level to respect user privacy.

### Delivery Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msgstore_deliveries_total` | Counter | domain, status | Total message deliveries |
| `msgstore_delivery_duration_seconds` | Histogram | domain | Delivery latency |
| `msgstore_delivery_size_bytes` | Histogram | domain | Message sizes |

### Authentication Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msgstore_auth_attempts_total` | Counter | domain, status | Authentication attempts |

The `status` label indicates success or failure (e.g., `success`, `failed`).

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
