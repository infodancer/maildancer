# Signing Key Rotation Design

**Status:** Proposed
**Scope:** `infodancer/auth` (auth-oidc)
**Related:** [auth-oidc.md](auth-oidc.md), [oidc-federation-design.md](https://github.com/infodancer/infodancer/blob/master/docs/oidc-federation-design.md)

---

## Problem

auth-oidc currently issues one RS256 keypair per domain, stored at `{data_dir}/{domain}/signing.key` and never rotated. The `kid` is hardcoded as `{domain}-1`. JWKS advertises a single public key. There is no provision for retiring an old key, advertising multiple keys during a transition window, or limiting blast radius if a signing key is exposed.

Application-layer encryption of the key file is *not* the right primary defense — the decryption key has to live somewhere reachable by the unattended-startup service, which limits how much that control can buy against any threat FDE + filesystem perms doesn't already cover (see "Out of scope" below for the threat-model reasoning). The lever that actually moves the needle is rotation: bound the lifetime of any single key so that an exposure has a finite blast radius regardless of how it happened.

## Goals

- Every signing key has a bounded lifetime. Default: 90 days as `current`, then a retention window as `retiring`, then deleted.
- JWKS advertises every key that could verify a token a relying party might still hold. Multiple keys are normal.
- Rotation is zero-downtime. No window where token validation fails for a relying party that has refreshed JWKS recently.
- Emergency revocation is supported. An operator can mark a key as compromised and remove it from JWKS immediately, accepting the consequence that in-flight tokens signed by that key will fail.
- Migration from the existing single-key layout is silent and lossless. No tokens signed before the upgrade fail to verify after it.
- **Algorithm agility.** Algorithm is a per-key attribute, not a server-wide constant. Rotating from one algorithm to another is just a rotation where the new key uses a different algorithm; the retiring key continues to verify older tokens until it expires. This is the lever for eventual post-quantum migration when the JOSE ecosystem catches up.

## Non-goals

- Application-layer encryption of key files at rest. Threats: root compromise and process compromise are unaffected by file encryption (the key is in memory during normal operation). Disk theft is covered by FDE. Backup theft is the residual threat; for deployments where that matters, `systemd-creds` / `LoadCredentialEncrypted` is the right addition and can be added independently of this design. This document does not block on that decision.
- Forced algorithm migration. The design accommodates per-key algorithm choice and operator-driven algorithm rotation, but does not auto-migrate existing RS256 deployments to anything else. Choice of algorithm for new keys is a server-config decision.
- Cross-host key sharing for HA replicas. auth-oidc remains a per-host service. If multi-host shared state ever materialises, the `Store` interface and per-domain key tables here are the right seam to add it; that's a future question.
- HSM / TPM-backed signing. Same reasoning — additive, separate decision.
- Implementing post-quantum signing today. JWA has no finalised identifier for ML-DSA yet and no mainstream OIDC RP library verifies post-quantum signatures. Implementing PQC signing now would produce tokens nothing can verify. The schema and rotation flow are designed to accept it later; see "Future: post-quantum migration".

## Key states

```
                generated
                    │
                    ▼
                ┌─────────┐
   on rotation  │ current │  ◄── used to sign all new tokens
        ┌──────►│ (one    │
        │       │  per    │
        │       │  domain)│
        │       └────┬────┘
        │            │ rotation
        │            ▼
        │       ┌──────────┐
        │       │ retiring │  ◄── still in JWKS; verifies older tokens
        │       └────┬─────┘
        │            │ expires_at <= now
        │            ▼
        │       ┌─────────┐
        │       │ expired │  ◄── removed from JWKS; file deleted on next sweep
        │       └─────────┘
        │
        └── on compromise: skip retiring, jump straight to expired
```

Invariants:
- Exactly one `current` key per domain at any time.
- Zero or more `retiring` keys per domain. JWKS publishes `current` + all `retiring`.
- `expired` is a transient state during sweep — the row and file are both removed.

## Algorithm choice

The current single-key design is hardcoded to RS256. RS256 is the OIDC baseline because it has universal RP-library support, not because it is the best cryptographic choice. ES256 (ECDSA P-256) has smaller keys, faster signing and verification, no PKCS1v15 padding footguns, and is supported by every modern OIDC RP library. EdDSA (Ed25519) is cryptographically the strongest of the three but RP-library support is patchier than ES256.

**Default for new keys: `ES256`.** Configurable via `default_signing_algorithm`. Supported values in the initial implementation: `RS256`, `ES256`, `EdDSA`. The schema is open to additional algorithms without migration.

Per-key algorithm storage is what makes algorithm rotation work in the same code path as key rotation. Concretely:

- A `current` key has exactly one algorithm.
- `retiring` keys can have different algorithms from `current` — for example, an RS256 key may be retiring while an ES256 key is current after an algorithm-rotation event.
- JWKS publishes all keys regardless of algorithm; RPs select by `kid` and use whatever `alg` the JWK declares.
- The discovery document's `id_token_signing_alg_values_supported` is the set union of algorithms across all `current` + non-expired `retiring` keys for the requested domain, computed at request time. Once the last RS256 key has been swept, RS256 is no longer advertised.

**Quantum safety.** None of RS256, ES256, EdDSA are quantum-safe — Shor's algorithm breaks RSA and all classical ECC. The NIST-standardised post-quantum signature algorithms (ML-DSA per FIPS 204, SLH-DSA per FIPS 205) cannot be used today because JWA has not finalised identifiers and no mainstream OIDC RP library verifies them. The algorithm-agility design in this document is the lever for that future migration. See "Future: post-quantum migration" below.

## Retention window

A `retiring` key must remain in JWKS long enough that every token signed by it while it was `current` will have expired before the key disappears. The lower bound is `jwt_ttl_sec` (the maximum lifetime of any token this server issues; default 1h). The safety margin accounts for clock skew between this server and relying parties, and relying parties that cache JWKS aggressively.

**Default retention after retire: `24 × jwt_ttl_sec`** (24h with default config). Configurable.

This is generous on purpose. The cost of carrying an extra public key in JWKS is trivial; the cost of a relying party failing to validate a still-valid token is real operational noise.

## Storage

Per the project's storage principle (key material on the filesystem with kernel-enforced ownership; high-churn relational state in SQLite), this design splits across both layers:

**Filesystem.** Private key material stays in PEM files with 0600 perms, owned by the auth-oidc service user. New layout:

```
{data_dir}/{domain}/
  signing.key            # LEGACY — read on first startup, then migrated away
  keys/
    {kid}.key            # one file per active or retiring key
```

**SQLite.** Key metadata lives in the existing OIDC state database (the one introduced by #44), in a new table:

```sql
CREATE TABLE signing_keys (
    domain      TEXT NOT NULL,
    kid         TEXT NOT NULL,
    algorithm   TEXT NOT NULL,       -- 'RS256' | 'ES256' | 'EdDSA' | future: 'ML-DSA-65'
    state       TEXT NOT NULL CHECK (state IN ('current', 'retiring')),
    created_at  INTEGER NOT NULL,
    retired_at  INTEGER,             -- when state moved current → retiring
    expires_at  INTEGER,             -- when this row + file should be deleted
    PRIMARY KEY (domain, kid)
) STRICT;

CREATE INDEX idx_signing_keys_domain_state ON signing_keys(domain, state);
CREATE INDEX idx_signing_keys_expires_at   ON signing_keys(expires_at)
    WHERE expires_at IS NOT NULL;
```

The PEM file format encodes algorithm in its header (`RSA PRIVATE KEY`, `EC PRIVATE KEY`, etc.), so the `algorithm` column is redundant with the on-disk material but is kept in the table as the authoritative metadata. The loader cross-checks: if the DB says ES256 and the file decodes as an RSA key, that's a corruption signal and startup fails loudly.

Why split: a single SQLite row containing the PEM would mix encryption-at-rest concerns (which want filesystem-level perms and FDE) with rotation metadata (which wants atomic state transitions and indexed sweeps). Splitting keeps each layer doing what it's best at and preserves the option to add `systemd-creds`-style at-rest wrapping to the key files later without touching the metadata model.

**Atomicity.** A rotation is one SQL transaction that updates the outgoing `current` row to `retiring` and inserts the new `current` row. The new key file is written and fsynced before the transaction commits; the old file stays in place until the sweep removes it after `expires_at`.

## `kid` scheme

Format: `{domain}-{unix_nanoseconds}` where the timestamp is the key's `created_at` in nanoseconds since the Unix epoch. Example: `infodancer.net-1747700000123456789`.

Properties:
- Sortable (so log analysis can compare timestamps without joining to the DB).
- Globally unique within the domain. Nanosecond resolution eliminates collisions for any realistic rotation cadence — even back-to-back manual rotations during testing won't collide.
- Opaque to relying parties — they treat `kid` as a string lookup against JWKS.
- The legacy `kid` `{domain}-1` is preserved for the pre-rotation key during migration (see below). New rotations always use the timestamp form.

## Rotation procedure

```
1. Pick algorithm:
     - scheduled rotation: server config default_signing_algorithm
     - manual rotation:    explicit --algorithm flag wins; otherwise default
2. Generate new keypair for the chosen algorithm (crypto/rand source):
     - RS256:  rsa.GenerateKey(rand.Reader, 2048)
     - ES256:  ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
     - EdDSA:  ed25519.GenerateKey(rand.Reader)
3. Compute kid = "{domain}-{now_unix}".
4. Write {data_dir}/{domain}/keys/{kid}.key (tmpfile + fsync + atomic rename, 0600).
   PEM type matches the algorithm (RSA PRIVATE KEY, EC PRIVATE KEY, PRIVATE KEY for Ed25519).
5. BEGIN TRANSACTION
     UPDATE signing_keys
       SET state = 'retiring',
           retired_at = now,
           expires_at = now + retention_after_retire
       WHERE domain = ? AND state = 'current';
     INSERT INTO signing_keys (domain, kid, algorithm, state, created_at)
       VALUES (?, ?, ?, 'current', now);
   COMMIT
6. Reload the in-memory keyStore entry for this domain.
7. Future signing uses the new key + algorithm; JWKS now publishes both;
   discovery's id_token_signing_alg_values_supported now reflects the union.
```

Step 6 reloads from disk + DB rather than mutating in-memory state directly. This keeps "what's published" and "what's on disk" reconciled by a single code path. The keyStore exposes a `Reload(domain)` method called by the rotation routine and the background scheduler.

Algorithm rotation (e.g. RS256 → ES256) is the same procedure — the new key just happens to use a different algorithm than the retiring one. No special case in code.

## Triggers

**Scheduled.** A background goroutine started by `Server.New` runs daily (interval configurable). For each domain, it checks whether the `current` key's `created_at` is older than `key_rotation_interval` (default 90 days) and rotates if so. Scheduled rotations use `default_signing_algorithm` for the new key.

**Manual.** Folded into the existing `userctl` operator CLI as a `keys` subcommand namespace. `userctl` is already the auth-oidc operator's tool — it runs locally, requires filesystem access to the data directories, and is not intended for client-domain end users. Adding key operations there keeps operator surface in one binary:

- `userctl keys list <domain>` — print all keys for a domain (kid, algorithm, state, created/retired/expires timestamps).
- `userctl keys rotate <domain>` — force rotation now using `default_signing_algorithm`. Useful for testing, scheduled-maintenance windows, and pre-emptive rotation before an operator vacation.
- `userctl keys rotate <domain> --algorithm=ES256` — force rotation with an explicit algorithm. This is how operators migrate a domain from one algorithm to another.
- `userctl keys revoke <domain> <kid>` — emergency. Marks the key as expired immediately, removing it from JWKS on the next reload. Operator accepts that any token signed by `<kid>` is now unverifiable.

The CLI talks to the same SQLite database the server uses. It does not require the server to be stopped; rotation operations are atomic and the server reloads on the next request that touches the key (or via a SIGHUP / inotify watch — implementation detail, see "Open questions").

The `userctl users …` and `userctl keys …` namespaces stay distinct in the help output; key operations do not need to know about user state and vice versa.

## Sweep

The existing 5-minute sweep goroutine (introduced by #44) gains one additional query:

```sql
DELETE FROM signing_keys
  WHERE expires_at IS NOT NULL AND expires_at <= ?
  RETURNING domain, kid;
```

For each returned row, the sweeper unlinks `{data_dir}/{domain}/keys/{kid}.key`. The file unlink is best-effort and logged; if it fails (e.g. file already missing), the operation continues — the DB row deletion is the authoritative state change.

## Migration from the existing single-key layout

On startup, for each domain:

```
if {data_dir}/{domain}/keys/ does not exist:
  if {data_dir}/{domain}/signing.key exists:
    # Pre-existing single-key deployment. Migrate.
    mkdir {data_dir}/{domain}/keys/ (0700)
    rename signing.key → keys/{domain}-1.key
    INSERT signing_keys (
      domain, kid='{domain}-1', algorithm='RS256', state='current',
      created_at=<file mtime>
    )
  else:
    # Fresh install. Generate first key.
    generate new keypair with default_signing_algorithm
    INSERT signing_keys (
      domain, kid="{domain}-{now}", algorithm=<default>, state='current',
      created_at=now
    )

else:
  # Already migrated. Load all rows for domain from signing_keys.
  read all key files referenced by current+retiring rows
  build in-memory keyStore for domain (one entry per kid, with its algorithm)
```

The legacy `kid` `{domain}-1` and its RS256 algorithm are preserved deliberately. Any token signed before the upgrade still has `{domain}-1` in its header; relying parties looking that `kid` up in JWKS will continue to find it, and they will verify it with the RS256 algorithm the JWK declares. The migrated key is the `current` key — it keeps signing new tokens with the same `kid` and algorithm until the first rotation, at which point it transitions to `retiring` and a new timestamp-form `kid` (using the configured `default_signing_algorithm`) becomes `current`.

This produces a single, silent, lossless upgrade path. No release-notes warning needed. If the operator wants the domain on ES256 immediately, they run `userctl keys rotate <domain>` after upgrade and the new `current` key is ES256.

## JWKS and discovery publication

`GET /.well-known/jwks.json` returns the union of:
- The `current` key for the requested domain.
- All `retiring` keys for the requested domain (where `expires_at > now`).

Public keys only. Each JWK carries its own `kid`, `alg` (RS256 / ES256 / EdDSA / future), and `use=sig`. No JWKS-side distinction between current and retiring; relying parties don't need to know which key is the active signer. They select by `kid` from the token header and trust the JWK's declared `alg`.

`GET /.well-known/openid-configuration` returns `id_token_signing_alg_values_supported` as the **set union of algorithms across all current + non-expired retiring keys** for the requested domain, computed at request time:

```
SELECT DISTINCT algorithm FROM signing_keys
  WHERE domain = ?
    AND (state = 'current' OR (state = 'retiring' AND expires_at > now))
```

This means the advertised algorithm set shrinks naturally as old-algorithm keys expire. During a RS256 → ES256 migration, both are advertised; once the retiring RS256 key is swept, only ES256 is advertised, and clients lose any reason to attempt RS256 against this issuer.

## Configuration additions

```toml
[server]
# Algorithm used when generating new keys (first-time generation and
# scheduled rotation). Existing keys keep their own algorithm.
# Supported: "RS256", "ES256", "EdDSA".
default_signing_algorithm = "ES256"

# Default rotation interval. The scheduled rotator triggers when a current
# key's age exceeds this.
key_rotation_interval = "2160h"   # 90 days

# How long a key stays in JWKS after being retired. Floor is jwt_ttl_sec
# plus clock-skew margin; default is intentionally generous.
key_retention_after_retire = "24h"

# How often the scheduled rotator wakes up to check key ages. Independent
# of the 5-minute sweep cadence used for codes/sessions.
key_rotation_check_interval = "24h"
```

Durations are parsed via `time.ParseDuration`. Missing values fall back to defaults. `default_signing_algorithm` is validated against the supported set at startup; an unknown value fails startup with a clear error rather than silently falling back.

## Future: post-quantum migration

The algorithm-per-key model is what makes the eventual post-quantum migration tractable. The expected sequence:

1. **Wait for the ecosystem.** JWA finalises an identifier for ML-DSA (most likely `ML-DSA-65` per current drafts). Mainstream OIDC RP libraries — at minimum `go-oidc`, `jose-jwt`, `python-jose`, `node-jose` — add verification support. Browsers' WebAuthn-style ecosystems may move first; auth-oidc waits until OIDC RP libraries catch up because issuing tokens nothing can verify is worse than not issuing them.
2. **Add `MLDSA65` to the supported algorithm set in auth-oidc.** This requires a Go library that can generate ML-DSA keys and sign/verify ML-DSA JWTs. The standard library's `crypto/mldsa` (when it lands) is the preferred dependency; a third-party `go-mldsa` is the fallback. JWK encoding follows the finalised JOSE PQC draft.
3. **Hybrid period (optional).** Some deployments may want to dual-sign with both a classical and a PQC key during transition — issue two JWTs or extend the JWT to carry two signatures (per current PQC JOSE drafts). This design does *not* commit to hybrid signing; the choice can be made when the time comes. If it's needed, the `current` slot would gain a "co-current" sibling rather than mutate the state enum.
4. **Operator-driven rotation per domain.** `userctl keys rotate <domain> --algorithm=ML-DSA-65` introduces the PQC key as `current`. The classical key becomes `retiring` for the standard retention window. JWKS publishes both; RPs that understand ML-DSA use the new key, RPs that don't fall back to the retiring classical key until it expires.
5. **Bandwidth cost.** ML-DSA-65 signatures are ~3.3KB and public keys are ~1.95KB. JWT size grows accordingly. Operators with bandwidth-sensitive deployments will want to know this; document it when the time comes.
6. **Retire classical algorithms.** Once all RPs in a deployment's relevant ecosystem can verify PQC tokens, scheduled rotation can be allowed to retire the last classical keys naturally. The discovery endpoint will stop advertising classical algorithms after the last retiring key expires.

Nothing in this future plan requires the v1 design to change. The schema accepts new algorithm strings; the rotation procedure is algorithm-agnostic; JWKS publishes whatever's in the table. The only code change at that point is "add ML-DSA to the supported-algorithms switch in the key generator and PEM/JWK encoder."

## What this design does NOT do

Stated explicitly so future contributors don't add these without a new design pass:

- **No per-key audit log table.** Rotations are logged via the existing `slog` channel; the `signing_keys` table records the authoritative state but not history. If history becomes valuable, add a `signing_key_events` table — don't load the live state table with event records.
- **No automatic rotation on detected compromise.** Compromise is an operator decision; the CLI exposes it as an explicit `revoke` action.
- **No notification to relying parties on rotation.** OIDC relying parties are expected to refresh JWKS on `kid` miss; this design relies on that contract.
- **No backwards-compatibility code path for "single-key mode".** After the migration runs once, the new layout is the only layout. The legacy `signing.key` file is removed by the migration step.

## Open questions

1. **Server reload coordination.** When `userctl keys rotate` runs against the DB, how does the running server pick up the new state? Three options: (a) the server polls the DB on every signing request (simple, slight overhead), (b) the server watches the DB file with inotify and reloads on change (more code, no overhead), (c) operator sends SIGHUP after running `userctl keys rotate` (explicit, requires documentation discipline). Recommendation: (a) for v1 — the overhead is one indexed query per token issuance and the simplicity is worth it. Revisit if profiling shows it matters.
2. **Key-rotation observability.** Should rotation events be exposed as a Prometheus counter (`auth_oidc_key_rotations_total{domain}`)? Probably yes — cheap, useful for "is rotation actually happening on my deployments". Default to yes; defer to implementation if there's a reason not to.
3. **Test strategy for the 90-day timer.** The scheduled rotator's age check is trivial to unit-test by injecting a clock; the rotation procedure itself wants integration tests that span the file + DB layers, similar to the existing `store_contract_test.go` pattern.
