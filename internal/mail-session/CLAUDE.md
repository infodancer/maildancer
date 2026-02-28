# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`mail-session` is a privilege-separated mail retrieval agent. It is spawned by the
pop3d or imapd dispatcher after successful authentication, running as `uid=user,
gid=domain`. It handles all maildir operations over a line-based session pipe protocol
and exits when the session ends or the pipe closes.

Part of the [infodancer mail stack](https://github.com/infodancer/infodancer). The
full process separation model is defined in:
https://github.com/infodancer/infodancer/blob/master/docs/mail-security-model.md

## Architecture

```
/cmd/mail-session/   # Entrypoint: reads config, opens mailbox, runs protocol loop
/internal/protocol/  # Session pipe protocol parser and command dispatch
/internal/session/   # Session state: selected mailbox, deletion marks, flags
/errors/             # Centralized error definitions
```

### Session Pipe Protocol v1

Commands arrive on stdin, responses go to stdout. All lines are CRLF-terminated.

```
# Commands
MAILBOX <mailbox>          → opens mailbox (must be first command)
LIST                       → list messages: +OK <count>\r\n<uid> <size> <flags>\r\n...
STAT                       → +OK <count> <total-bytes>
GET <uid>                  → +DATA <size>\r\n<message bytes>
HEADERS <uid> [<lines>]    → +DATA <size>\r\n<headers[+lines body lines]>
DELETE <uid>               → +OK
UNDELETE <uid>             → +OK
COMMIT                     → apply deletes, exit 0
QUIT                       → exit without committing
FOLDERS                    → +OK <count>\r\n<name>\r\n... (future: IMAP)
SELECT <folder>            → +OK <count> messages (future: IMAP)
SETFLAG <uid> <flag>       → +OK (future: IMAP)
CLEARFLAG <uid> <flag>     → +OK (future: IMAP)
APPEND <folder> <flags> <size>\r\n<bytes>  → +OK (future: IMAP)

# Responses
+OK                        → success, no data
+OK <data>                 → success with single-line data
+OK <count>                → followed by <count> CRLF-terminated lines
+DATA <size>               → binary blob of <size> bytes follows immediately
-ERR <reason>              → error
```

### Uid/Gid Drop

`mail-session` is spawned with `SysProcAttr.Credential` set by the dispatcher.
It never calls `setuid`/`setgid` itself — the dispatcher handles privilege drop.

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
- Use `crypto/rand` for security-sensitive random generation
- Never expose internal error details over the protocol pipe

## Versioning & Releases

`mail-session` and `mail-deliver` use **synchronized versioning** — both repos
must always be at the same version tag.

**Version scheme**: `v0.0.x` during pre-release development.

Tag with:
```bash
git tag v0.0.1
git push origin v0.0.1
```

GoReleaser will build cross-platform binaries automatically.
