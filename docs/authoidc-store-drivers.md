# auth-oidc state store: pluggable drivers (file default, redis optional)

Status: design (decided, not yet implemented). Written 2026-07-24 from the
analysis in GitHub issue #181. This doc is the durable record -- the issue will
close. It deliberately records the *reasoning*, including the arguments that
were overturned, so the decision is not re-litigated from scratch.

## One-line summary

auth-oidc's `Store` moves off `modernc.org/sqlite` to two first-class drivers:
`file` (the default, no external dependencies) and `redis` (optional, for real
cross-host HA). SQLite is dropped because its one remaining advantage --
multi-process safety -- turns out to buy no actual high availability, while
costing ~250 MB of dependency for a single package's worth of use.

## What the store actually holds

`authoidc.Store` (`internal/auth/authoidc/store.go`) persists four things:

| Data | Volume | Durability need |
|---|---|---|
| Authorization codes | bursty, short-lived | Low -- single-use, 10-minute TTL |
| SSO sessions | one per logged-in user | **High** -- 7-day default TTL |
| Registered clients | few per domain | High -- dynamic registration |
| Signing-key metadata | few per domain | **Critical** -- see below |

The signing-key rows are the only genuinely irreplaceable data. The key *PEM
material* already lives on the filesystem at
`{data}/{domain}/keys/{kid}.key`; the store holds the metadata saying which kid
is `current`, which are `retiring`, and when retiring rows may be swept. Lose
that and auth-oidc cannot identify its current signing key, so token issuance
breaks for every domain at once.

### Actual TTLs

These drive driver behaviour and must be read from config, never hardcoded per
driver. (An earlier draft of this design hardcoded a 60-second code TTL into the
Redis sketch, which would have expired authorization codes nine minutes early
and broken any slow authorization flow.)

| Value | Default | Source |
|---|---|---|
| Authorization code TTL | 10 minutes | `handlers.go` |
| SSO session TTL | 7 days | `config.go` -- `session_ttl_sec` (604800) |
| JWT TTL | 1 hour | `config.go` -- `jwt_ttl_sec` (3600) |
| Key rotation / retention | 90 days / 24h after retire | `server.go` |
| Sweep interval | 5 minutes | `server.go` -- `sweepInterval` |

## Why SQLite was there in the first place

Worth stating, because the new design partially reverts it and that should be a
conscious choice rather than an accident.

`sqliteStore` was introduced in commit `eb20960` to *replace* a file-per-record
filesystem store from the pre-consolidation `infodancer/auth` repo. It bought
three things:

1. **ACID transactions** -- notably for signing-key rotation, where
   `current -> retiring` plus inserting the new current key must be atomic.
2. **Indexed expiry sweeps** -- `DELETE ... WHERE expires_at <= ?` against an
   index, constant work regardless of how many live entries exist.
3. **`DELETE ... RETURNING` atomicity for `ConsumeCode`** -- exactly one
   concurrent winner falls out of SQLite's write serialisation rather than a
   process-level mutex. A 32-way concurrent test proved it.

It also matched the driver choice already shipped in `infodancer/webauth`, so
the static-binary (no cgo) deployment story stayed consistent across the auth
stack.

## Why it goes anyway

The cost is disproportionate: `modernc.org/sqlite` plus its `libc`, `mathutil`,
and `memory` transitive deps is roughly 250 MB extracted per version, pulled in
by exactly one package (`go mod why` shows `internal/auth/authoidc` as the sole
path) and one file. It is the pure-Go SQLite -- there is no lighter pure-Go
SQLite to swap to, so keeping SQL means keeping the weight.

Of the three original justifications, only the atomicity guarantees are load
bearing, and both are reproducible without SQL:

- Reason 2 (indexed sweeps) is a non-problem at this data volume, and Redis
  removes it entirely via native TTL expiry.
- Reason 3 (`ConsumeCode` atomicity) holds within a single process using a
  mutex, and across processes using Redis `GETDEL`.

That leaves multi-process safety as SQLite's only real remaining edge -- and it
does not deliver what it appears to:

- **Two daemons on the same host share a failure domain.** SQLite's WAL +
  `busy_timeout` genuinely supports several processes against one database file,
  but co-located replicas do not provide high availability. If the host dies,
  both die.
- **SQLite across hosts is unsafe.** File locking over a network filesystem is
  unreliable and risks corruption, so the multi-host case -- the only one that
  would be real HA -- was never available.

So the 250 MB was buying a capability that provides no availability benefit.

## Rejected alternatives

Recorded so they are not revisited without new information.

- **bbolt (`go.etcd.io/bbolt`).** Superficially attractive: pure Go, ACID,
  roughly 100x smaller. Rejected because it takes an **exclusive flock** on
  open, making it single-process *by construction* -- strictly worse than
  SQLite on the very axis being evaluated, while still adding a dependency.
- **PostgreSQL.** Would give genuine cross-host HA, and Postgres already exists
  in the wider homelab. Rejected as a *hard* dependency: auth-oidc is a leaf IdP
  that otherwise needs nothing but local files, and coupling it to a network
  database inverts that. Acceptable later as an additional pluggable driver if a
  need appears.
- **Keeping SQLite.** Defensible on inertia, but it fails the cost/benefit above.
  Note the CI symptom that first surfaced this (a ~1.8 GB module cache being
  re-uploaded every job) was fixed independently by disabling `setup-go`'s
  redundant cache (infodancer/workflows#16); that fix is not a reason to keep the
  dependency, it just removes the recurring tax.
- **In-memory sessions in the default driver.** Rejected once the real TTL was
  checked: sessions default to **7 days**, so discarding them on restart would
  log every user out of SSO on every deploy. Codes are a different case (see
  below).

## The design

Two drivers behind the existing `Store` interface, selected by config. The
interface already exists and is exercised by a table-driven contract test, so
this is adding implementations rather than reshaping the abstraction.

### `file` -- default, no external dependencies

- **Signing-key metadata** -> per-domain JSON written next to the PEMs under
  `{data}/{domain}/keys/`. Atomic temp-write + rename, with fsync of both the
  file and its directory. The "exactly one `current` key per domain" invariant
  becomes trivial here: it is a single document rewritten wholesale, so the
  invariant is a property of the document rather than something a partial unique
  index has to enforce.
- **SSO sessions** -> on disk. 7-day TTL makes durability necessary, and the
  write volume is trivial (one write per login, one delete per logout).
- **Registered clients** -> on disk, same atomic-write pattern.
- **Authorization codes** -> in memory, mutex-guarded. A 10-minute, single-use
  code that does not survive a restart costs a retry at worst, and
  `ephemeralStore.ConsumeCode` already performs read-and-delete under one lock,
  which is exactly-one-winner within a process.
- **Sweeps** -> in-memory sweep for codes; on-disk sweep for sessions and for
  signing-key retention.

This aligns with how auth-oidc already works: the config tree and key material
are files, and the repo already uses atomic temp+rename in several places
(`auth/passwd/manage.go`, `auth/domain/forwardedit.go`,
`msgstore/maildir/uidlist.go`).

### `redis` -- optional, for cross-host HA

Redis is the right optional backend specifically because it is **already
present**: `github.com/redis/go-redis/v9` is a direct dependency of this module
(smtpd greylisting, IMAP notifications) and rspamd already runs a Redis in the
deployment. So the HA path adds no new infrastructure, and `miniredis` (also
already a dependency) makes it testable without a live server.

- **Codes** -> `SET` with expiry; consume with **`GETDEL`**, which atomically
  returns and deletes. This is the direct analogue of SQLite's
  `DELETE ... RETURNING` and preserves exactly-one-winner *across* daemons.
- **Sessions** -> `SET`/`GET`/`DEL` with expiry from `session_ttl_sec`.
- **Clients** -> hash per domain.
- **Signing keys** -> hash per domain. Rotation runs as a **Lua script** so the
  `current -> retiring` transition plus the new-current insert is atomic and the
  one-current-per-domain invariant is enforced server-side.
- **Sweeps** -> effectively a no-op for codes and sessions; native TTL expiry
  replaces the indexed sweep that was one of SQLite's original justifications.
  Only signing-key retention needs an explicit sweep, since it has its own
  semantics.

All TTLs come from the existing config values, never per-driver constants.

## Invariants any driver must uphold

These are the contract, independent of backend:

1. **`ConsumeCode` yields exactly one winner** under concurrency. A replayable
   authorization code is a security defect, not a race to tolerate.
2. **Exactly one `current` signing key per domain**, at all times.
3. **Rotation is atomic** -- a domain must never be observed with no current key
   mid-rotation.
4. Expired codes and sessions are not returned, whether or not a sweep has run.

## Testing

`internal/auth/authoidc/store_contract_test.go` is a table over implementations
(currently `ephemeral` and `sqlite`) and is the enforcement point: new drivers
are added as rows.

**Do this first:** the 32-way exactly-one-winner test currently lives in
`sqlitestore_test.go` as `TestSQLiteStore_ConsumeCode_Concurrent`, so it only
covers SQLite. Promote it into the contract before adding drivers, so `file` and
`redis` must both prove invariant 1 rather than inheriting an untested claim.

## Migration (must not be skipped)

`oidc-state.db` is the only record of which kid is `current`. That is **not**
recoverable from the PEM filenames on disk, so removing the SQLite driver
without migrating leaves auth-oidc unable to identify its signing key for every
domain -- an outage of exactly the kind this component has caused before.

Decision: a **documented manual procedure**, not an export command. The
deployment has one real operator and a small domain count, so the cost of
tooling is not justified. The procedure reads the `signing_keys` rows out of
`oidc-state.db` and writes the per-domain JSON, and it must be written down and
executed **before** the release that removes the driver.

## Implementation order

1. Promote the concurrency test into the contract test.
2. Implement the `file` driver; make it the default.
3. Implement the `redis` driver (tested against `miniredis`).
4. Config-select the driver; replace the hardwired `newSQLiteStore` calls in
   `server.go` and `keymanager.go` with a factory.
5. Write and run the manual migration procedure.
6. Delete `sqlitestore.go` and `sqlitestore_test.go`; drop `modernc.org/*` from
   `go.mod`.

## Note on webauth

`infodancer/webauth` (separate repo) also uses `modernc.org/sqlite` with goose
migrations, and `sqlitestore.go`'s comments cite that consistency as part of the
original rationale. This change diverges auth-oidc from it. That is accepted:
the two services have different shapes -- webauth is the federation broker with
tenant management, auth-oidc is a leaf IdP with a few small documents of state.
webauth carries its own copy of the dependency in its own repo and is unaffected
by this decision.
