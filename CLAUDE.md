# CLAUDE.md

Guidance for Claude Code when working in the **maildancer** monorepo.

## What this is

maildancer is the consolidated mail server suite and local-filesystem auth for
infodancer — a single Go module (`github.com/infodancer/maildancer`) holding the
former `smtpd`, `pop3d`, `imapd`, `session-manager`, `mail-session`,
`mail-remote`, `queue-manager`, `msgstore`, `auth`, and
`webadmin` repositories. Full history of each was preserved on import
(`git log --follow` and `git blame` work through the moves).

Cross-cutting design documents live in the separate **infodancer/infodancer**
repo under `docs/` (security model, encryption design, OIDC federation, queue
design, etc.). Read them there.

> ## ⚠️ Identity & OIDC — READ BEFORE TOUCHING AUTH
>
> Before changing `auth/`, `internal/authoidc`, `webauth` (separate repo), or
> any auth path, read **infodancer/docs/oidc-federation-design.md**. The three
> hard rules:
>
> 1. **auth-oidc is a leaf IdP — NEVER a federation client.** It authenticates
>    owned mail-domain users against local passwd files and exposes OIDC +
>    webfinger. No upstream, no RP/callback code.
> 2. **webauth is the ONLY federation client** (it lives in its own repo).
> 3. **Websites are dumb RPs** — they never talk to auth-oidc or any upstream
>    directly.

## Layout

```
msgstore/            Shared storage library + interfaces (DeliveryAgent,
                     AuthProvider, MessageStore, FolderStore). Top-level,
                     importable. Maildir-backed.
auth/                Authentication & key management (AuthRouter, KeyProvider,
                     domain, passwd, forwards). Top-level, importable.
cmd/<binary>/        Entrypoints: smtpd pop3d imapd session-manager
                     mail-session mail-remote queue-manager
                     auth-oidc userctl webadmin
internal/<module>/   Daemon implementations (not importable outside the module)
internal/authoidc/   OIDC server implementation behind cmd/auth-oidc
```

The flatten decision: `msgstore` and `auth` are top-level because they are the
shared, reusable libraries; the daemons live under `internal/` because nothing
outside this module consumes them.

## Build / test

Uses [Task](https://taskfile.dev/):

```bash
task build          # build all binaries into ./bin
task test           # go test -race ./...
task lint           # golangci-lint run ./...
task vulncheck      # govulncheck ./...
task all            # build + lint + vulncheck + test
task hooks:install  # configure git to use .githooks
```

Run a single test: `go test -run TestName ./internal/<module>/...`

## Architectural boundaries (enforced by depguard)

The privilege-separation model is encoded as lint rules in `.golangci.yml`:
the protocol daemons (`smtpd`, `pop3d`, `imapd`) **must not** import `msgstore`,
`auth`, or `auth/*` directly — authentication, domain routing, and delivery all
go through `session-manager` over gRPC. Violations fail `task lint`. If you need
a daemon to reach storage or auth, route it through session-manager; do not
relax the depguard rule.

## Address & delivery contracts

Violating these reintroduces bugs the design deliberately avoids.

- **Address normalization happens in exactly one place: `auth/domain.AuthRouter`.**
  After domain auth it sets `User.Mailbox` to `base@domain` (fully-qualified,
  subaddress stripped) and returns the extension separately in
  `AuthResult.Extension`. The daemons (`smtpd`, `pop3d`, `imapd`) pass
  `User.Mailbox` (or the raw envelope `localpart@domain`) **straight through** to
  `msgstore` — they must **not** add localpart extraction or domain-stripping
  logic. `msgstore` strips the domain internally (or applies `path_template`).
  Enforced by `TestAuthRouterMailbox_AddressContract` in `auth/domain`.
- **Privilege separation:** `session-manager` spawns `mail-session` with
  `SysProcAttr.Credential{Uid, Gid}`; the agent never calls `setuid`/`setgid`
  itself — it starts already running as the recipient user.
- **mail-session sessions are not thread-safe.** Its gRPC server mutex-serializes
  access to `session.Session`; RPCs are otherwise stateless (folder in every
  request). `DeliveryService` (in `mail-session`) is the delivery path.
- **Forwarding is 1-hop.** A delivery that resolves a forward re-delivers exactly
  once; a second forward in that chain is an error, not followed — this prevents
  mail loops.

## Next-gen protocols (scmp / sdmp)

`scmp` and `sdmp` are **separate external repos**, deliberately not part of this
monorepo, because they are published wire contracts meant for third-party
implementation (and are also consumed by the `messagedancer` desktop client).
When they thaw, maildancer will implement them as new daemons here (`cmd/scmpd`,
`cmd/sdmpd`) that *import* the external protocol modules — the dependency arrow
points maildancer → scmp/sdmp, never the reverse.

## Versioning

Single repo, single version tag: `v0.N.X`. Minor `N` is a human decision (never
bump without explicit approval); patch `X` auto-increments on release. Pre-1.0
until production-ready.

## Workflow

- GitHub issue before branching; branch `feature/<issue>` or `bug/<issue>`.
- Small, logical, separate commits. Commits reference the issue.
- PRs merge to `main` (never ask the user to merge).
- See `CONVENTIONS.md` for Go coding standards.
