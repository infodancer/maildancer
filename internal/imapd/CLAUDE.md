# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`imapd` is an IMAP server implementation in Go. It implements the IMAP4rev1 protocol (RFC 3501) and integrates with the `msgstore` library for message storage and the shared `AuthProvider` interface for authentication.

## Architecture

```
/cmd/imapd/         # Entrypoint only
/internal/imap/     # IMAP protocol implementation
/internal/session/  # Per-connection session state
/errors/            # Centralized error definitions
```

### Address Contract

imapd passes `User.Mailbox` from the `AuthResult` directly to the message store — it does **not** normalise or strip the domain. `AuthRouter` guarantees that `User.Mailbox` is set to `base@domain` (fully-qualified, subaddress stripped) after domain authentication. The store then strips the domain internally.

Do not add localpart extraction or domain stripping logic in imapd. Any address handling belongs in `auth/domain.AuthRouter` or `msgstore`. Test sessions must use fully-qualified mailboxes (e.g. `"testuser@example.com"`) to reflect real runtime behaviour.

## Development Commands

```bash
task build          # Build the binary
task test           # Run tests with race detector
task vet            # go vet
task fmt            # Check formatting
task fmt:fix        # Fix formatting
task lint           # golangci-lint
task vulncheck      # govulncheck
task check          # Run all CI checks
task hooks:install  # Install git hooks
```

### Running a Single Test

```bash
go test -v -run TestName ./path/to/package
```

## Development Workflow

### Branch and Issue Protocol

**This workflow is MANDATORY.** All significant work must follow this process:

1. **Create a GitHub issue first** — draft an issue describing the purpose and design. Assign to the requesting user. Ask for approval before proceeding.
2. **Create a feature or content branch** — only after issue approval. Use `feature/UUID` or `bug/UUID` naming.
3. **Reference the issue in all commits** — every commit message must include the issue URL.
4. **Stay focused on the issue** — no unrelated refactors, fixes, or improvements.
5. **Handle unrelated problems separately** — file a separate issue; don't address in the current branch.

## Best Practices

### Commit Practices

- Atomic commits — one logical change per commit
- Build and verify locally before committing

### Pull Request Workflow

- All branches merge to main via PR
- PRs must reference the originating issue
- **NEVER ask users to merge or approve a PR** — that is always a manual user action
- After creating a PR, check out main before starting further work

### Security

- Never commit secrets, credentials, or tokens
- Validate all external input at system boundaries
- Use `crypto/rand` for security-sensitive random generation
- Set timeouts on all network operations
- Never expose internal error details to IMAP clients

Read CONVENTIONS.md for Go coding standards.
