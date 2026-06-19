# auth

Authentication, domain routing, identity allocation, and key management for
maildancer. Importable library; it also backs two binaries: `cmd/auth-oidc` (the
leaf OIDC IdP) and `cmd/userctl` (the site-operator CLI).

`auth-oidc` is a leaf identity provider: it authenticates a domain's own mail
users and exposes OIDC discovery for them. It is not an OIDC client and has no
upstream provider. The full auth design lives in the
[`infodancer/infodancer`](https://github.com/infodancer/infodancer) docs.

## Pluggable auth agents

Authentication backends implement `AuthenticationAgent` and register by name,
mirroring the msgstore pattern:

```go
agent, err := auth.OpenAuthAgent(auth.AuthAgentConfig{ /* ... */ })
// auth.RegisteredAuthAgents() lists what's registered
// auth.RegisterAuthAgent(name, factory) adds one (call from an init())
```

A successful `Authenticate` yields an `AuthSession` carrying the `User`
(including the normalized `Mailbox`). Import a provider for its registration side
effect, e.g. `import _ "github.com/infodancer/maildancer/auth/passwd"`.

## Subpackages

| Package | Responsibility |
|---|---|
| `passwd` | File-based provider (argon2id hashes). The default local backend. |
| `oauth` | OAuth 2.0 bearer-token validation (SASL OAUTHBEARER). |
| `domain` | Per-domain config, the postmaster map, and `AuthRouter` -- the **one** place address normalization happens. |
| `forwards` | Forwarding-rule loading and 1:1 resolution (exact match beats catchall). |
| `identity` | The single read/write code path for OS uid/gid allocation (`gid.toml`, `{domain}/uid.toml`). |
| `keyring` | Client keyring and the key-encryption-key (KEK) layer. |
| `keyseal` | The single interface between key generation and at-rest sealing. |
| `keys` (top level) | `KeyProvider` -- NaCl key management used by the encryption path. |

## Address normalization (the contract)

`domain.AuthRouter` is the only normalizer: after domain authentication it sets
`User.Mailbox` to `base@domain` (fully-qualified, subaddress stripped) and
returns any `+extension` separately. Daemons pass `User.Mailbox` straight through
to `msgstore`; they do not add their own localpart/domain handling. This is
enforced by `TestAuthRouterMailbox_AddressContract`.

## Identity is not configuration

OS uid/gid are allocated once and are authoritative -- they are exempt from the
site -> domain -> user config merge hierarchy and are written only through the
`identity` package (via `userctl` or `webadmin`). See
[`docs/`](docs/) and the identity-allocation design doc in `infodancer/infodancer`.
