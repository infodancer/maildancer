# webadmin

Web administration interface for the mail server suite. Provides domain management, user management, encryption key management, mailbox statistics, RBAC, audit logging, and Prometheus metrics through a REST API with a server-rendered HTML UI (HTMX + Pico CSS + Chart.js).

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
- `internal/middleware/` - Auth, CSRF, RBAC access control, rate limiting, security headers, request logging
- `internal/handlers/` - HTTP handlers for REST API and web UI
- `internal/handlers/templates/` - Go html/template files (embed.FS)
- `internal/server/` - HTTP server setup and route registration
- `internal/rbac/` - Role-based access control (super_admin / domain_admin)
- `internal/audit/` - JSON audit logger with context-based admin tracking
- `internal/keys/` - NaCl X25519 keypair generation and management
- `internal/metrics/` - Prometheus metric definitions
- `errors/` - Centralized error definitions

## Configuration

Uses TOML configuration with a `[webadmin]` section. See `webadmin.toml.example` for all options.

```toml
[webadmin]
listen_address = "localhost:8080"
domains_path = "/var/mail/domains"

[webadmin.auth]
passwd_file = "/etc/webadmin/admin-passwd"
# Optional: restrict admins to specific domains
# roles_file = "/etc/webadmin/admin-roles.toml"

[webadmin.audit]
# Optional: write JSON audit lines to file (also always emits via slog)
# log_file = "/var/log/webadmin/audit.log"

[webadmin.session]
timeout_minutes = 30

[webadmin.tls]
cert_file = "/etc/ssl/certs/mail.pem"
key_file = "/etc/ssl/private/mail.key"
```

## RBAC

When `roles_file` is set, admins are restricted by role. Without it, all authenticated admins have super_admin access (backward compatible).

`roles.toml` format:
```toml
[admins.alice]
role = "super_admin"
domains = []

[admins.bob]
role = "domain_admin"
domains = ["example.com", "test.com"]
```

- **super_admin**: full access to all domains, plus `/api/roles`, `/api/audit`, create/delete domains
- **domain_admin**: read/write access to assigned domains only

RBAC is managed via `GET/POST/DELETE /api/roles/{username}` (super_admin only).

## API Routes

### Public
- `GET /health` — health check
- `GET /login`, `POST /login` — authentication
- `GET /metrics` — Prometheus metrics

### Dashboard
- `GET /` — dashboard UI (domain list + Chart.js bar chart)
- `GET /api/dashboard` — JSON stats: domain count, total users, per-domain breakdown

### Domain Management
- `GET /api/domains` — list domains (filtered by RBAC)
- `GET /api/domains/{name}` — domain detail
- `POST /api/domains` — create domain (super_admin only)
- `DELETE /api/domains/{name}` — delete domain (super_admin only)

### Domain Keys
- `GET /api/domains/{name}/keys` — key status + fingerprint
- `POST /api/domains/{name}/keys` — generate NaCl X25519 keypair
- `DELETE /api/domains/{name}/keys` — remove domain keypair

### User Management
- `GET /api/domains/{domain}/users` — list users
- `POST /api/domains/{domain}/users` — create user
- `DELETE /api/domains/{domain}/users/{username}` — delete user
- `PUT /api/domains/{domain}/users/{username}/password` — reset password

### User Keys
- `GET /api/domains/{domain}/users/{username}/keys` — key status
- `POST /api/domains/{domain}/users/{username}/keys` — generate keypair
- `DELETE /api/domains/{domain}/users/{username}/keys` — remove keypair

### Admin (super_admin only)
- `GET /api/audit` — last 100 audit log entries
- `GET/POST/DELETE /api/roles/{username}` — RBAC management

## Key Encryption Format

Both domain and user private keys use the same wire format:
`salt(32B) || nonce(24B) || secretbox.Seal(privkey)`

The key is derived from the supplied password using argon2id (t=3, m=64MB, p=4).

## Docker

```bash
# Build image
docker build -t webadmin .

# Local dev with Prometheus
docker compose up
```

See `docker-compose.yml` and `prometheus.yml` for compose/scrape config.
Mount config at `/etc/webadmin/webadmin.toml` inside the container.

## Security Model

This repository is part of the infodancer mail stack. The process separation,
privilege model, uid/gid allocation, and pipe protocol are defined in:

https://github.com/infodancer/infodancer/blob/master/docs/mail-security-model.md
