# All-in-one image

The whole maildancer stack in a single container, supervised by
[s6-overlay](https://github.com/just-containers/s6-overlay). This is the common,
obvious deployment -- one image to reason about. The per-component images (one
binary each, e.g. `cmd/queue-manager/Dockerfile`) remain for operators who want
to isolate or independently scale each daemon.

Published as `ghcr.io/infodancer/maildancer/all-in-one`.

## What runs inside

s6 supervises these long-running services (see `rootfs/etc/s6-overlay/s6-rc.d/`):

| Service | Invocation | Notes |
|---|---|---|
| session-manager | `/session-manager -config …` | comes up first; owns the per-user session socket and spawns `/mail-session` |
| smtpd | `/smtpd serve -config …` | ports 25 / 465 / 587 |
| pop3d | `/pop3d serve -config …` | ports 110 / 995 |
| imapd | `/imapd -config …` | ports 143 / 993 |
| queue-manager | `/queue-manager --config … --queue … --binary /mail-remote` | outbound; spawns `/mail-remote` |
| webadmin | `/webadmin -config …` | port 8080 |

`userctl` and `auth-oidc` are also installed at `/` for `docker exec` use
(user/key provisioning, the leaf IdP) but are not started as services.

Startup ordering is declarative via `dependencies.d/`: everything depends on
session-manager, which depends on the s6 `base` bundle.

## Why it must run as root

Privilege separation in maildancer is **uid/gid-based**, not container-based:
session-manager spawns mail-session and smtpd spawns its protocol-handler /
mail-deliver children under per-user, per-domain uids via
`SysProcAttr.Credential`. The container therefore needs root (or `CAP_SETUID` +
`CAP_SETGID`). Putting the daemons in one container does not weaken that
boundary -- the boundary was always the uid, never the container.

## What stays outside

redis, rspamd, and clamav remain compose sidecars -- they are upstream images,
not maildancer's to repackage. The all-in-one is "one image" for *our* code.

## Volumes / config

Identical to the per-container deployment; the shared `config.toml` already has
a section per daemon:

- `/etc/infodancer` -- config (`config.toml`, `domains/`)
- `/opt/infodancer/domains` -- mail data
- `/etc/letsencrypt` -- TLS certs
- `/var/spool/mail-queue` -- outbound queue

## Build

Context is the repository root:

```bash
docker build -f docker/all-in-one/Dockerfile -t maildancer-all-in-one .
```

For a private `infodancer/logging` fetch, pass a token:

```bash
docker build --secret id=github_token,src=<(gh auth token) \
    -f docker/all-in-one/Dockerfile -t maildancer-all-in-one .
```
