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
- **smtpd / pop3d / imapd** mount *only* the socket volume -- never `maildata`.
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

- **Via webadmin** (`http://localhost:8080`) -- create a domain and users in the
  UI. You first need an admin credential in `deploy/config/admin-passwd`
  (RBAC is disabled by default, so any authenticated user is super_admin --
  set `roles_file` to enable RBAC).
- **Via CLI** -- `userctl`. It is a CLI, not one of the service images; run it
  from a build or a one-off container that mounts both the config and data
  volumes. The order is create domain, add user, then reconcile ids/perms:

  ```bash
  userctl domain create example.com            # allocates the domain gid
  userctl user   add    matthew@example.com    # allocates the user uid; prompts for password
  userctl domain fix    --all                  # allocates any missing ids + repairs data-dir perms (run as root)
  ```

  `domain fix` is idempotent: re-running it allocates only what is missing and
  re-applies ownership. In the deploy it runs on every converge after the
  declarative `domain create` / `user add` steps.

webadmin and userctl share the same operations layer (`internal/admin`), so the
two front doors cannot drift -- a domain or user created in one is fully managed
by the other.

auth-oidc serves discovery per owned domain (host-based routing); with zero
domains, `/.well-known/openid-configuration` returns 404 until a domain exists.

## Identity allocation (uid / gid)

Each mail domain is an OS group and each local user is an OS user; the data dirs
under `{data}/{domain}/` are `2750 root:{gid}` and per-user maildirs are
`{uid}:{gid}`. Those uid/gid values are **identity allocation, not
configuration** -- allocated once, authoritative, and exempt from the
site -> domain -> user override hierarchy that governs `config.toml`. Putting a
uid or gid in a merged config file is the exact mistake that once locked a live
mailbox out of IMAP (the password verified, but `mail-session` spawned with a
gid that could not traverse the data dirs, surfacing as `AUTHENTICATIONFAILED`).

For the default local passwd-files provider, identity lives in two flat maps in
the **config** tree, written only by the shared identity package (via `userctl`
or `webadmin`):

| File | Contents | Example |
|------|----------|---------|
| `{config}/gid.toml` | domain -> gid (one top-level map for the whole site) | `"example.com" = 10014` |
| `{config}/{domain}/uid.toml` | localpart -> uid (per domain) | `"matthew" = 10026` |

`{config}/{domain}/passwd` holds only credentials and is now three fields --
`username:argon2id_hash:mailbox`. The uid is **not** in passwd; it lives in
`uid.toml`. (Older deployments had a fourth uid field; `userctl domain fix`
adopts that uid into `uid.toml` and then narrows the passwd line.)

Rules that the tooling enforces and you should not work around:

- **Never hand-edit `gid.toml` / `uid.toml`, and never render them from IaC.**
  They are an allocation ledger, not config. Let `userctl` / `webadmin` write
  them.
- **Allocate once; never reassign a live id.** The allocator refuses to
  overwrite an existing entry. Repair means chowning data to the recorded id,
  never minting a new id to match the data -- which is exactly what
  `userctl domain fix` does.
- **The data tree never holds an authoritative id.** `{data}/{domain}/` carries
  maildirs, keyrings, and the allocator's `.uid-counter`, but no gid of record.
- **A domain using LDAP or a database provider does not use these files at all**
  -- its identities come from that backend. Only the *choice* of provider is
  hierarchical config; the ids a provider records are not.

To migrate a deployment that predates the maps, `userctl migrate uids` (or
`domain fix --all`) walks every domain, adopting any id already authoritative
under the old layout before allocating a fresh one, so existing mail is never
re-owned out from under itself.

The full rationale and design history is in
`infodancer/infodancer/docs/identity-allocation-design.md` (authoritative). Read
it before changing anything in the auth, session-manager, or userctl id paths.

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
  permissions (`chmod 600`) -- git cannot preserve restrictive modes.
- The outbound queue handoff (session-manager → `mailqueue` → queue-manager)
  uses the shared volume; verify the queue path matches your `[queue-manager]`
  config in production.
