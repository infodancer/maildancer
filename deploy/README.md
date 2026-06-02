# maildancer deployment (docker-compose)

A full mail-suite stack for local development and deploy validation.

```bash
docker compose up -d           # from the repo root
docker compose ps
docker compose logs -f session-manager
docker compose down            # add -v to also wipe the data volumes
```

## Topology

```
            ┌─────────────── mail network ───────────────┐
  :25/587   │   smtpd ─┐                                  │
  :110      │   pop3d ─┼─ unix socket ─▶ session-manager ─┼─▶ maildata (storage)
  :143      │   imapd ─┘  (sessmgr-sock)   │  (hub)       │   mailqueue ─▶ queue-manager ─▶ mail-remote
            │                              └─ redis       │
  :8080     │   webadmin ─────────────────── maildata     │
  :9000     │   auth-oidc ───────────────── maildata (ro) │
            └─────────────────────────────────────────────┘
```

- **session-manager** is the hub: it owns the mail storage (`maildata`) and the
  outbound queue (`mailqueue`), and listens on a unix socket shared with the
  protocol daemons via the `sessmgr-sock` volume. It spawns the bundled
  `mail-session` per user (so it runs as root to set per-user uid/gid).
- **smtpd / pop3d / imapd** mount *only* the socket volume — never `maildata`.
  This matches the depguard privilege-separation boundary: the network-facing
  daemons have no filesystem access to mail data. smtpd hands both inbound
  delivery and outbound submission to session-manager.
- **queue-manager** drains the shared `mailqueue` and invokes `mail-remote`.
- **redis** backs smtpd greylisting and IMAP notifications.
- **webadmin** (`:8080`) administers domains/users on `maildata`.
- **auth-oidc** (`:9000`) is the leaf OIDC IdP; it reads per-domain passwd files
  (read-only) and keeps its own state under `authoidc-data`.

Config lives in `deploy/config/`: `config.toml` (shared by the mail daemons),
`webadmin.toml`, `auth-oidc.toml`, and `admin-passwd`.

## What's validated

`docker compose up -d` brings the whole stack up. The daemons answer on their
ports (`220`/`+OK`/`* OK` banners), session-manager listens on the socket, and
webadmin serves its UI.

## Provisioning (required for actual mail flow)

A fresh stack has no domains or users, so login and delivery won't work until you
provision one. The `init` one-shot creates an empty `/var/mail/domains`; populate
it with a domain and user:

- **Via webadmin** (`http://localhost:8080`) — create a domain and users in the
  UI. You first need an admin credential in `deploy/config/admin-passwd`
  (RBAC is disabled by default, so any authenticated user is super_admin —
  set `roles_file` to enable RBAC).
- **Via CLI** — `userctl --domains <path> add user@domain` (prompts for a
  password) against the `maildata` volume. `userctl` is a CLI, not one of the
  service images; run it from a build or a one-off container that mounts the
  volume.

auth-oidc serves discovery per owned domain (host-based routing); with zero
domains, `/.well-known/openid-configuration` returns 404 until a domain exists.

## Outbound relay & TLS

Inbound delivery and POP3/IMAP retrieval work out of the box over plaintext
(25/587, 110, 143). **Outbound** relay by authenticated users additionally needs
TLS, because smtpd only advertises `AUTH` after `STARTTLS` (it refuses plaintext
credentials off-localhost). To enable authenticated submission:

```bash
./deploy/gen-dev-certs.sh              # self-signed dev cert into deploy/certs/
# uncomment [server.tls] in deploy/config/config.toml
docker compose up -d
```

The certs mount (`./deploy/certs:/etc/ssl/mail`) is already wired into smtpd/pop3d/
imapd; it's empty until you run the script. The outbound queue is pre-configured
(`[session-manager.queue]`), so once a user can authenticate, submitting to an
external address enqueues to `mailqueue` and queue-manager drains it to mail-remote.

The implicit-TLS ports (465/995/993) come up once `[server.tls]` is set and the
matching listeners are added. Do not run plaintext submission/retrieval over an
untrusted network.

## Notes

- `admin-passwd` is a placeholder; create a real credential and tighten its
  permissions (`chmod 600`) — git cannot preserve restrictive modes.
- The outbound queue handoff (session-manager → `mailqueue` → queue-manager)
  uses the shared volume; verify the queue path matches your `[queue-manager]`
  config in production.
