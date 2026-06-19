# cmd

Entrypoints for the maildancer binaries. Each subdirectory is a `main` package
that wires up configuration and starts a daemon or runs a CLI; the real
implementation lives under `internal/` (daemons) or in the top-level `auth` /
`msgstore` libraries.

## Operator-facing

These are the binaries you run and configure directly.

| Binary | Role | Listens on |
|---|---|---|
| `smtpd` | Inbound SMTP + authenticated submission | 25, 465, 587 |
| `pop3d` | POP3 retrieval | 110, 995 |
| `imapd` | IMAP retrieval | 143, 993 |
| `session-manager` | Auth + per-user session hub; spawns `mail-session` | unix socket |
| `queue-manager` | Outbound queue driver; invokes `mail-remote` | - |
| `webadmin` | Web admin UI (domains, users, keys) | 8080 |
| `auth-oidc` | Leaf OIDC identity provider for owned domains | 9000 |
| `userctl` | Site-operator CLI (domains, users, forwards, keys) | - (CLI) |

`userctl` is the host-side admin tool; run `userctl` with no arguments for the
full subcommand list. See [`../deploy/README.md`](../deploy/README.md) for the
provisioning flow.

## Spawned agents (not run directly)

These are launched by other processes with reduced privileges; operators don't
start them by hand.

| Binary | Spawned by | Runs as |
|---|---|---|
| `mail-session` | session-manager | `uid=user, gid=domain` |
| `mail-remote` | queue-manager | outbound delivery worker |

(`mail-deliver`, the smtpd delivery agent, is built from `internal/` and spawned
by smtpd the same way.)

Build everything into `./bin` with `task build`.
