# auth - Authentication and Key Management

Provides authentication services and encryption key management for the
infodancer mail system.

## Features

- User authentication with password validation
- Public/private key management for message encryption
- Pluggable authentication backends (passwd, ldap, database)
- Argon2id password hashing
- NaCl-based key encryption

## Backends

### passwd

File-based authentication similar to Unix passwd format.

Features:
- Argon2id password hashing
- Per-user encryption keys stored encrypted
- Simple file-based configuration

File format:
```
username:$argon2id$v=19$m=65536,t=3,p=4$salt$hash:mailbox
```

## Usage

```go
import (
    "github.com/infodancer/maildancer/auth"
    _ "github.com/infodancer/maildancer/auth/passwd"  // Register passwd backend
)

config := auth.AuthAgentConfig{
    Type:              "passwd",
    CredentialBackend: "/etc/mail/passwd",
    KeyBackend:        "/etc/mail/keys",
}

agent, err := auth.OpenAuthAgent(config)
if err != nil {
    // handle error
}
defer agent.Close()

session, err := agent.Authenticate(ctx, "username", "password")
if err != nil {
    // handle auth failure
}

// session.User contains authenticated user info
// session.PrivateKey contains decrypted private key (if encryption enabled)
```

## Key Management

The auth package provides `KeyProvider` interface for retrieving public keys
for encryption without requiring full authentication.

```go
keyProvider := agent.(auth.KeyProvider)  // passwd.Agent implements both

pubKey, err := keyProvider.GetPublicKey(ctx, "username")
if err != nil {
    // handle error
}

hasEncryption, err := keyProvider.HasEncryption(ctx, "username")
if err != nil {
    // handle error
}
```

## Implementing Backends

To implement a new authentication backend:

1. Implement the `auth.AuthenticationAgent` interface
2. Optionally implement `auth.KeyProvider` if your backend supports encryption
3. Register your backend with `auth.RegisterAuthAgent()`

Example:

```go
package myauth

import "github.com/infodancer/maildancer/auth"

type MyAgent struct {
    // your fields
}

func (a *MyAgent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
    // your implementation
}

func (a *MyAgent) Close() error {
    // cleanup
}

func init() {
    auth.RegisterAuthAgent("myauth", func(config auth.AuthAgentConfig) (auth.AuthenticationAgent, error) {
        return NewMyAgent(config)
    })
}
```

See `passwd/` for a complete reference implementation.

## Security

- Passwords are hashed with Argon2id (memory-hard key derivation)
- Private keys are encrypted with user passwords using NaCl secretbox
- Constant-time comparison for password verification
- No plaintext credentials stored on disk

## Architecture

The auth package is designed to be independent of message storage:

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│  smtpd  │     │  pop3d  │     │  imapd  │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │ KeyProvider   │ AuthAgent     │ AuthAgent
     │               │               │
     └───────────────┴───────────────┘
                     │
              ┌──────┴──────┐
              │    auth     │
              └─────────────┘
```

- `smtpd` uses `KeyProvider` for encrypting messages to recipients
- `pop3d` and `imapd` use `AuthenticationAgent` for user authentication
- Auth is completely independent of message storage (msgstore)

## Development

### Available Tasks

Run `task --list` to see all available tasks:

| Task | Description |
|------|-------------|
| `task build` | Build the library |
| `task lint` | Run golangci-lint |
| `task vulncheck` | Run govulncheck for security vulnerabilities |
| `task test` | Run tests |
| `task test:coverage` | Run tests with coverage report |
| `task all` | Run all checks (build, lint, vulncheck, test) |

### Git Hooks

This project includes a pre-push hook that runs all checks before pushing. To enable it:

```bash
task hooks:install
```
