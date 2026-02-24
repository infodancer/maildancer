# webadmin

Web administration interface for the mail server suite. Provides domain management, user management, encryption key management, and mailbox statistics through a REST API with a server-rendered HTML UI (HTMX + Pico CSS).

## Build

```bash
go build ./...

# Or via Task
task build
```

## Test

```bash
go test -race ./...

# Or via Task
task test
```

## Lint

```bash
# Requires golangci-lint v2
golangci-lint run ./...

# Or via Task
task lint
```

## Vulnerability Check

```bash
govulncheck ./...

# Or via Task
task vulncheck
```

## All CI Checks

```bash
task check
```

## Architecture

- `cmd/webadmin/main.go` - Entrypoint
- `internal/config/` - TOML configuration parsing
- `internal/session/` - Cookie-based session management with CSRF tokens
- `internal/middleware/` - Auth, CSRF, rate limiting, security headers, request logging
- `internal/handlers/` - HTTP handlers for REST API and web UI
- `internal/handlers/templates/` - Go html/template files (embed.FS)
- `internal/server/` - HTTP server setup and route registration
- `errors/` - Centralized error definitions

## Configuration

Uses TOML configuration with a `[webadmin]` section. See `webadmin.toml.example` for all options.

```toml
[webadmin]
listen_address = "localhost:8080"
domains_path = "/var/mail/domains"

[webadmin.auth]
passwd_file = "/etc/webadmin/admin-passwd"

[webadmin.session]
timeout_minutes = 30

[webadmin.tls]
cert_file = "/etc/ssl/certs/mail.pem"
key_file = "/etc/ssl/private/mail.key"
```
