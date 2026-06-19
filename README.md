# maildancer

A federated mail server suite and local-filesystem authentication stack, in a
single Go module. maildancer consolidates what used to be the separate smtpd,
pop3d, imapd, session-manager, mail-session, mail-remote, queue-manager,
msgstore, auth, and webadmin repositories, with their full history preserved.

The design goal is a mail system that is **secure by separation**: no
network-facing process can touch mail on disk, and no single process ever holds
credentials for more than one user at a time.

> **Status: pre-1.0.** The suite runs and is in real use, but interfaces,
> on-disk formats, and config keys may still change between minor versions. Not
> yet recommended for unattended production deployment by third parties. See
> [per-component TODOs](#status--maturity) for what is and isn't finished.

## What's in the box

| Binary (`cmd/`) | Role | Ports |
|---|---|---|
| `smtpd` | Inbound SMTP + authenticated submission. SPF, DKIM, DMARC, SASL, STARTTLS, PIPELINING, CHUNKING/BDAT, Redis greylisting. "Reject early, never bounce." | 25, 465, 587 |
| `pop3d` | POP3 retrieval (RFC 1939 + CAPA/TOP/UIDL/STARTTLS/SASL) | 110, 995 |
| `imapd` | IMAP4rev1 (RFC 3501, via go-imap/v2) | 143, 993 |
| `session-manager` | Auth + per-user mail-session lifecycle hub; the only process that touches mail storage and the outbound queue | unix socket |
| `mail-session` | Per-user retrieval/delivery agent, spawned as `uid=user, gid=domain` | (spawned) |
| `mail-deliver` | Delivery agent: forwarding -> rspamd -> sieve -> maildir write | (spawned) |
| `mail-remote` | Outbound delivery agent invoked by the queue | (invoked) |
| `queue-manager` | Outbound queue driver: retry loop, TTL cleanup | — |
| `webadmin` | Web admin UI (domains, users, keys; RBAC, audit log) | 8080 |
| `auth-oidc` | Leaf OIDC identity provider for owned mail domains | 9000 |
| `userctl` | Site-operator CLI (domains, users, forwards, keys) | — |

The two importable libraries live at the top level: **`msgstore`** (storage
interfaces and the maildir backend) and **`auth`** (authentication, domain
routing, identity allocation, key management). The daemons live under
`internal/` because nothing outside this module consumes them.

## Architecture

```
        ┌──────────────────────── network ─────────────────────────┐
  25/587 │  smtpd ─┐                                                 │
  110    │  pop3d ─┼─ unix socket ─▶ session-manager ─▶ mail-session │ ─▶ maildirs
  143    │  imapd ─┘                  (auth + hub)      (per-user uid)│
         └───────────────────────────────┬───────────────────────────┘
                                          │
   smtpd ─▶ queue-manager ─▶ mail-remote ─┘ ─▶ outbound SMTP
```

Privilege separation is **uid/gid-based, not container-based**: session-manager
(running as root) spawns `mail-session` and smtpd spawns `mail-deliver` with
`SysProcAttr.Credential{Uid, Gid}` set to the recipient user and domain group.
The network daemons (`smtpd`/`pop3d`/`imapd`) have no filesystem access to mail
data and reach storage and auth only through session-manager over gRPC -- a
boundary enforced at lint time by depguard rules in `.golangci.yml`.

At-rest mail is encrypted with NaCl box (X25519 + XSalsa20-Poly1305); smtpd
encrypts before delivery and pop3d/imapd decrypt after retrieval, so msgstore
only ever handles encrypted blobs.

The authoritative design documents -- security model, encryption design, OIDC
federation, queue design, identity allocation -- live in the separate
[`infodancer/infodancer`](https://github.com/infodancer/infodancer) repository
under `docs/`.

## Quick start

Bring up the full stack with Docker Compose from the repo root:

```bash
docker compose up -d
```

This starts smtpd, pop3d, imapd, session-manager, queue-manager, webadmin
(http://localhost:8080), auth-oidc (http://localhost:9000), and Redis.

A fresh stack has no domains or users, so mail flow won't work until you
provision at least one. Use webadmin or the `userctl` CLI:

```bash
userctl domain create example.com         # allocates the domain's gid
userctl user   add    alice@example.com    # allocates a uid; prompts for a password
userctl domain fix    --all                # allocates any missing ids + repairs perms (run as root)
```

See [`deploy/README.md`](deploy/README.md) for the full topology, the
config-tree vs data-tree split, the identity-allocation model, TLS and outbound
relay setup, and teardown.

## Building

The project uses [Task](https://taskfile.dev/) and requires **Go 1.26+**.

```bash
task build      # build all binaries into ./bin
task test       # go test -race ./...
task lint       # golangci-lint run ./...
task vulncheck  # govulncheck ./...
task all        # build + lint + vulncheck + test
```

Run a single test with `go test -run TestName ./internal/<module>/...`.

## Status & maturity

Pre-1.0. The mail path (inbound, retrieval, authenticated submission, outbound
queue) works; encryption, privilege separation, and the admin tooling are in
place. Remaining work and protocol-coverage matrices are tracked in the
in-repo `TODO.md` files (`internal/smtpd/TODO.md`, `internal/pop3d/TODO.md`,
`msgstore/TODO_RECEIVED_HEADERS.md`).

The next-generation client/server protocols (`scmp`, `sdmp`) are deliberately
kept in separate repositories as published wire contracts; maildancer will grow
daemons that *import* them when they stabilize.

## Contributing

Contributions are welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow and [CONVENTIONS.md](CONVENTIONS.md) for Go coding standards. Security
issues should go through [SECURITY.md](SECURITY.md), not public issues.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
