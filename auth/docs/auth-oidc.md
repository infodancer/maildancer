# auth-oidc

`auth-oidc` is a lightweight OpenID Connect (OIDC) provider for the infodancer mail stack. It issues OIDC tokens using credentials from the same passwd/key store that the mail server uses, so mail accounts are the canonical identity source for all OIDC-protected services.

## Domain model

Each registered mail domain gets its own OIDC issuer at `https://auth.<domain>`. For example, `infodancer.net` is served by `https://auth.infodancer.net`. This is RFC 8414-compliant: the issuer is `scheme://host` with no path component.

**Host-based domain resolution**: the server resolves the domain by progressively stripping labels from the left of the `Host` header until a registered domain is found. This means any subdomain of a registered domain routes to that domain's issuer:

```
auth.infodancer.net  → registered? no → try infodancer.net → yes ✓
sso.infodancer.net   → registered? no → try infodancer.net → yes ✓
infodancer.net       → registered? yes ✓
```

Resolution stops before bare TLDs (single-label candidates are skipped). Unknown hosts return 404.

## OIDC flow

Only Authorization Code + PKCE (S256) is supported. Implicit flow and password grant are not implemented.

1. Client redirects user to `GET /authorize?response_type=code&client_id=...&code_challenge=...&code_challenge_method=S256&...`
2. Server renders a login form; user submits credentials via `POST /login`
3. On success, server redirects to the client's `redirect_uri` with `?code=...`
4. Client exchanges the code at `POST /token` with the PKCE verifier
5. Server returns `access_token` (JWT, RS256) and `id_token`
6. Client can fetch user info at `GET /userinfo` with `Authorization: Bearer <access_token>`

CSRF is protected with a double-submit cookie: a random token is set in a cookie and must also appear as a hidden field in the login form POST.

## Configuration

Config file location defaults to `/etc/auth-oidc/config.toml`; override with `AUTH_OIDC_CONFIG` env var.

```toml
[server]
listen           = ":8080"
data_dir         = "/var/lib/auth-oidc"   # stores per-domain RS256 keypairs
domain_data_path = "/opt/infodancer/domains"
jwt_ttl_sec      = 3600    # access token lifetime (default 1h)
session_ttl_sec  = 604800  # SSO session lifetime (default 7d)

[[client]]
domain        = "infodancer.net"
id            = "myapp"
# secret is empty for public clients (PKCE only)
redirect_uris = ["https://myapp.example.com/callback"]
```

Multiple `[[client]]` blocks are supported; each client belongs to one domain.

## Domain data layout

For each domain, the server expects the following layout under `domain_data_path`:

```
<domain_data_path>/
  <domain>/
    config.toml          # domain config (auth.credential_backend, auth.key_backend)
    passwd               # bcrypt password file (managed by userctl / webadmin)
    keys/                # DKIM and other per-domain keys
```

Example `config.toml`:

```toml
[auth]
type               = "passwd"
credential_backend = "passwd"
key_backend        = "keys"
```

The server generates RS256 keypairs in `data_dir` on first run; they persist across restarts.

## Dynamic client registration (RFC 7591)

When `registration_token` is set in the server config, clients can register themselves automatically without pre-configuration:

```
POST /register
Authorization: Bearer <registration_token>
Content-Type: application/json

{"client_name":"myapp","redirect_uris":["https://myapp.infodancer.net/callback"]}
```

Response (201):
```json
{"client_id":"abc123","client_id_issued_at":1234567890,"redirect_uris":[...],...}
```

The `registration_endpoint` URL is advertised in the discovery document so clients can find it automatically. Redirect URIs are validated against registered domains at registration time; the URI host must equal or be a subdomain of a registered mail domain.

Dynamic clients are always public (no client secret; PKCE required). On server restart the in-memory registry is cleared — services should register on startup if not already registered.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/.well-known/jwks.json` | Public keys for token verification |
| POST | `/register` | RFC 7591 dynamic client registration |
| GET | `/authorize` | Authorization endpoint (renders login form) |
| POST | `/login` | Login form handler |
| POST | `/token` | Token exchange |
| GET | `/userinfo` | Authenticated user info |
| POST | `/logout` | Clear SSO session |
| GET | `/healthz` | Health check |

## Deployment

`auth-oidc` is deployed on `docker-mail` as a separate Docker Compose stack. Traefik on `docker-web` routes all `auth.<domain>` hostnames to it via a dynamically-generated file provider config.

DNS: add an A record for `auth.<domain>` (or a wildcard `*.infodancer.net`) pointing to the Traefik host. TLS is handled by Traefik via Cloudflare DNS-01.

Each domain listed in `mail_domains` in the Ansible inventory gets a Traefik router rule automatically. To register OIDC clients, add `auth_oidc_clients` entries to the `docker-mail` host vars.
