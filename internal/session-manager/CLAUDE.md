# CLAUDE.md

This file provides guidance to Claude Code when working in the session-manager repository.

## Project Overview

Session manager for the infodancer mail stack. Centralizes authentication and
per-user mail-session process lifecycle management, enabling network-separated
deployments where protocol handlers (smtpd, imapd, pop3d) run on different
hosts from the mail store.

Design doc: `infodancer/infodancer/docs/session-manager-design.md`

## Architecture

```
smtpd ──┐
imapd ──┼──► session-manager ──► mail-session (uid=user, gid=domain)
pop3d ──┘     (auth + proxy)        unix socket
```

The session manager:
1. Authenticates users via the `auth` library (AuthRouter + DomainProvider)
2. Looks up uid/gid from per-domain config and passwd files
3. Spawns mail-session with `SysProcAttr.Credential` for uid isolation
4. Proxies MailboxService, FolderService, WatchService, and DeliveryService
   RPCs to the correct per-user mail-session
5. Manages session reuse (ref-counting) and idle reaping

## Development Commands

```bash
task build          # Build the binary (runs proto generation first)
task test           # Run tests with race detector
task lint           # Run golangci-lint
task vulncheck      # Check for vulnerabilities
task all            # Run all checks (build, lint, vulncheck, test)
task proto          # Regenerate proto Go code
task clean          # Remove build artifacts
```

## Key Dependencies

- `github.com/infodancer/maildancer/auth` — authentication (AuthRouter, DomainProvider, passwd)
- `github.com/infodancer/maildancer/internal/mail-session` — proto definitions + client library
- `google.golang.org/grpc` — gRPC server and client

## Development Workflow

### Branch and Issue Protocol

**This workflow is MANDATORY.** All significant work must follow this process:

1. **Create a GitHub issue first** — draft an issue describing the work. Ask the user to approve before proceeding.
2. **Create a feature branch** — `feature/UUID` or `bug/UUID` after issue approval.
3. **Reference the issue in all commits** — every commit must include the issue URL.
4. **Stay focused on the issue** — no unrelated changes.
5. **Handle unrelated problems separately** — file a separate issue.

### Pull Request Workflow

- All branches merge to main via PR
- PRs reference the originating issue
- **NEVER ask users to merge or approve a PR**
- After creating a PR, checkout main before starting further work

Read CONVENTIONS.md for Go coding standards.
