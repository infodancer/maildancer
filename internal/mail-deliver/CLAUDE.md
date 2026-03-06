# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project Overview

`mail-deliver` is the privilege-separated delivery agent for the infodancer mail stack.
It is spawned by smtpd (or any dispatcher) after a message is accepted, running as
`uid=recipient-user, gid=domain`. It handles forwarding resolution, spam checking,
sieve filtering, and final maildir write for a single message, then exits.

Part of the [infodancer mail stack](https://github.com/infodancer/infodancer). The
full process separation and privilege model is defined in:
https://github.com/infodancer/infodancer/blob/master/docs/mail-security-model.md

## Architecture

```
/cmd/mail-deliver/    # Entrypoint: reads stdin, calls deliver, writes response to stdout
/protocol/            # PUBLIC wire types — authoritative for the dispatcher/agent interface
/internal/config/     # TOML config loading ([maildeliver] section of shared config)
/internal/deliver/    # Delivery pipeline: forwarding → spam → sieve → maildir
/internal/rspamd/     # rspamd HTTP client
/errors/              # Centralized error definitions
```

### Privilege Model

The dispatcher (smtpd) sets `SysProcAttr.Credential{Uid: recipientUID, Gid: domainGID}`
on the child process before exec. mail-deliver **never** calls `setuid`/`setgid` itself —
it starts already running as the recipient user.

### Wire Protocol (see `protocol/` package)

**stdin**: JSON-encoded `DeliverRequest` (newline-terminated), followed by raw RFC 5322
message bytes until EOF. No uid/gid in the protocol — those are handled by the dispatcher.

**stdout**: JSON-encoded `DeliverResponse` (newline-terminated) before exit.

Response results:
- `"delivered"` — message written to maildir successfully
- `"rejected"` — delivery refused; `temporary=true` → 4xx, `false` → 5xx
- `"redirected"` — message should be re-delivered to `addresses`

### Forwarding (1-hop limit)

When a forwarding rule matches, mail-deliver returns `Result: "redirected"` with the
target addresses. The dispatcher re-delivers exactly **once** with `Forwarded: true`.
If the second delivery also returns `"redirected"`, that is an error — the dispatcher
must not follow it. This prevents mail loops.

Remote redirect targets (domains not locally served) are a temporary failure until
the outbound send queue is implemented.

### Delivery Pipeline

1. **Forwarding resolution** — three-level chain via `auth/domain` and `auth/forwards`:
   user-forwards file → domain forwards map → system forwards. Skipped when `Forwarded=true`.
2. **Spam check** — rspamd via HTTP; per-user and per-domain `spam.toml` override global config.
3. **Sieve** — script at `{data_path}/{domain}/users/{localpart}/.sieve` is parsed but
   not executed yet (execution to be added incrementally).
4. **Deliver** — `msgstore.DeliveryAgent.Deliver()` writes to the user's maildir.

### Config (`[maildeliver]` section of shared TOML)

```toml
[maildeliver]
domains_path = "/etc/mail/domains"
domains_data_path = "/var/mail"          # defaults to domains_path if omitted

[maildeliver.rspamd]
url = "http://localhost:11333"
timeout = "10s"
reject_threshold = 15.0
tempfail_threshold = 8.0
fail_mode = "tempfail"                   # open | tempfail | reject
```

Spam config lookup order (each level overrides the one above):
1. Global: `[maildeliver.rspamd]` in shared config
2. Domain: `{domains_path}/{domain}/spam.toml`
3. User: `{data_path}/{domain}/users/{localpart}/spam.toml`

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

## Development Workflow

### Branch and Issue Protocol

**This workflow is MANDATORY.** All significant work must follow this process:

1. **Create a GitHub issue first** — draft an issue describing the purpose and design.
   Assign to the requesting user. Ask for approval before proceeding.
2. **Create a feature or content branch** — only after issue approval. Use
   `feature/UUID` or `bug/UUID` naming.
3. **Reference the issue in all commits** — every commit message must include the
   issue URL.
4. **Stay focused on the issue** — no unrelated refactors, fixes, or improvements.
5. **Handle unrelated problems separately** — file a separate issue.

### Pull Request Workflow

- All branches merge to main via PR
- PRs must reference the originating issue
- **NEVER ask users to merge or approve a PR** — always a manual user action
- After creating a PR, check out main before starting further work

### Security

- Never commit secrets, credentials, or tokens
- All input from stdin is untrusted — validate before acting
- Never put uid/gid in the wire protocol
- Never call setuid/setgid inside mail-deliver

## Versioning

All infodancer repos follow a unified versioning policy defined in
[infodancer/infodancer CLAUDE.md](https://github.com/infodancer/infodancer/blob/main/CLAUDE.md).

- Only the patch version (`x` in `v0.N.x`) is auto-incremented when tagging.
- Never bump the minor version (`N`) without explicit human approval.
- All repos stay at `v0.x.y` (pre-1.0) until production-ready.
