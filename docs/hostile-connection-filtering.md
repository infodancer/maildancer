# Hostile connection filtering

Design for issue #206 (Redis-backed auth rate limiting and connection-level
banning). Status: implemented. Phases 1-5 are done; the outstanding work is
narrower than the original design and tracked in #221 and the open items below.
Read the issue and its first comment
for the production data this is built on; the numbers are not repeated here
beyond what the design turns on.

Related: #207 (TLS counters not wired -- found gathering the same data), #144
(outbound abuse control, which should reuse the limiter abstraction defined
here), #179/#189 (the fork-per-connection dispatcher this design hooks into).

## What the evidence forces

Three facts from the 24h/7d production sample drive every decision below.

1. **The spray is distributed and one-attempt-per-IP.** 59 source IPs in ~2h,
   41 of them making exactly one attempt. Per-IP attempt thresholds do not see
   this traffic at all.
2. **Most abusive connections never authenticate.** imapd took 2165 connections
   against 619 auth attempts. A gate that only runs on the auth path misses two
   thirds of it.
3. **Every username attempted was nonexistent.** That makes "attempted an
   account that does not exist" a first-attempt hostile signal with near-zero
   false positives, and it is the only signal that catches a one-attempt-per-IP
   spray.

Consequences: the primary rule is a **ban on a signal, not a threshold on a
counter**; it must be enforced **before the protocol starts**, not on the auth
path; and the state must be **shared across daemons and across process
restarts**, because the same IPs hit imapd and pop3d in the same window and the
handlers are one-shot subprocesses.

## Where the gate lives

`internal/connfork` is the single accept path for all three daemons
(`internal/imapd/backend/dispatch.go`, `internal/pop3d/pop3/dispatch.go`,
`internal/smtpd/smtp/subprocess.go` all construct a `connfork.Server`). One hook
there covers everything; there is no second accept loop to keep in sync.

This placement has three properties worth stating explicitly, because they are
what makes the design cheap:

- **The dispatcher parent is long-lived.** Handlers are one-shot subprocesses,
  so an in-process cache in a *handler* would be useless -- it dies with the
  connection. A cache in the parent survives, and absorbs reconnect storms.
- **The check runs pre-fork.** A banned IP costs no subprocess spawn, no TLS
  handshake, and no argon2id verify. The expensive work is exactly what the
  attacker is trying to make us do.
- **The parent holds no mail-data or auth privilege**, and gains none here --
  see the depguard resolution below.

### The connfork hook

As implemented:

```go
// PeerGate decides whether an accepted connection may reach a handler.
// A returned error means no verdict could be reached; the dispatcher then
// allows the connection unless Config.StrictGate is set.
type PeerGate interface {
    CheckPeer(ctx context.Context, ip string) (Verdict, error)
}

type Verdict struct {
    Banned bool          // denies the connection
    Tarpit time.Duration // how long to hold it first; zero closes immediately
    Reason string        // coarse policy label, for the dispatcher's logs only
}
```

`Banned` rather than the originally sketched `Allow` so the zero value is
"serve the connection": a gate that returns an empty verdict must not deny.
The error return is what lets connfork own the fail-open decision instead of
each implementation inventing its own.

`Config` gains `Gate` (nil = allow everything, preserving current behavior and
every existing test), `GateTimeout`, `StrictGate`, `MaxTarpit`, and the metric
callbacks. The check happens at the top of `spawnHandler`, before
`tcpConn.File()`.

### Token accounting -- the self-DoS hazard

`acceptLoop` acquires a `MaxConns` token *before* `Accept` so that excess
connections queue in the kernel backlog. A tarpit that holds that token for 30
seconds hands the attacker a trivial resource exhaustion: 59 IPs spraying a
daemon with `MaxConns=100` would fill the handler budget with sleeping sockets
and starve legitimate clients. The tarpit would become the vulnerability it was
added to mitigate.

So a denied connection **releases the handler token immediately** and acquires a
separate, smaller **tarpit token** (`MaxTarpit`, default 256). Over the tarpit
cap, denied connections close immediately instead of being held. Holding a
socket with no handler process behind it costs one fd and one goroutine, which
is why the two budgets can be sized independently.

Fd headroom is the real limit on `MaxTarpit`; the daemons should log the
configured `MaxConns + MaxTarpit` against `RLIMIT_NOFILE` at startup rather than
discovering the ceiling under attack.

## Resolving the depguard question

`.golangci.yml` forbids `smtpd`, `pop3d`, and `imapd` from importing `msgstore`,
`auth`, or `auth/*`. The rule stands; nothing here relaxes it.

**session-manager owns the policy, the Redis client, and the keyspace. The
daemons ask, and are told.** `SessionService` gains two RPCs:

```proto
// CheckPeer reports whether a peer IP is currently banned. Called by the
// protocol dispatchers at accept time, before any protocol or TLS work.
rpc CheckPeer(CheckPeerRequest) returns (CheckPeerResponse);

// ReportPeer records an abuse signal observed by a protocol handler that
// session-manager cannot see on its own (early talkers, malformed commands,
// aborted DATA). Fire-and-forget from the caller's perspective.
rpc ReportPeer(ReportPeerRequest) returns (ReportPeerResponse);
```

```proto
message CheckPeerRequest { string ip = 1; }

message CheckPeerResponse {
  bool banned = 1;
  // How long the dispatcher should hold a denied connection before closing.
  // Server-driven so policy stays in one place.
  int64 tarpit_ms = 2;
  // Opaque policy label for the daemon's logs and metrics. Deliberately
  // coarse -- never the username or the triggering signal.
  string reason = 3;
}

message ReportPeerRequest {
  string ip = 1;
  string signal = 2;  // "early_talker", "malformed_command", "data_abort", ...
}

message ReportPeerResponse {}
```

Recording of *auth* failures needs no new RPC: session-manager already performs
the authentication in `Login`, so it sees both the nonexistent-account case and
the wrong-password case and records them itself. Likewise RCPT probing is
already visible to it via `ValidateRecipient`. `ReportPeer` exists only for
signals that never reach session-manager.

The daemons therefore stay free of auth imports and of policy: they carry an IP
to `CheckPeer`, get back allow/deny plus a duration, and obey. `reason` is
deliberately coarse -- it is a policy label for our logs, never a description of
which signal fired, and never anything the client sees.

### Cost of the extra round trip

One unix-socket/mTLS gRPC call per accepted connection. At the measured volume
(2165 imapd connections/24h) this is nothing; under a flood it is exactly when
it matters, so:

- **Parent-side cache**, keyed by IP: deny entries cached for 60s, allow entries
  for 10s. A reconnect storm from a banned IP costs one RPC per minute per IP.
  Asymmetric TTLs because a stale allow is a missed ban for at most 10s, while a
  stale deny only over-punishes an IP that just earned a ban.
- **`GateTimeout`** (default 2s) bounds the call. Timeout is a gate error, not a
  deny; see fail-open policy below.
- The cache is bounded (default 8192 entries) so it is not itself a
  memory-exhaustion vector under a spray from many source addresses. Eviction
  ended up generational rather than LRU -- see the phase 3 decisions.

An allowlist of CIDRs is checked in the dispatcher *before* the RPC: loopback,
the monitoring network, and any operator-configured ranges are never gated and
never banned. This is the escape hatch that keeps a policy bug from locking the
operator out of their own mail server, and it costs no round trip.

## The three rules

### Rule 1: nonexistent account -> ban the IP

A `Login` naming an account that does not exist bans the source IP with a long
TTL, enforced thereafter at accept time by every daemon. One attempt is enough;
this is not a counter.

- Key: `peer:ban:<ip>`, value is a policy label, TTL as below.
- IPv6 bans apply to the **/64**, not the single address -- individual v6
  addresses are free to the attacker, so per-address banning is theater. Keyed
  `peer:ban:<prefix>` with the prefix normalized before lookup.
- Ban TTL: 24h on first offense, extended to 7d when an already-banned prefix
  reoffends after expiry (`peer:strikes:<prefix>`, 30d TTL). Fixed-TTL-only is
  the fallback if the strike counter proves noisy.
- Unban: `userctl peer unban <ip|prefix>` plus `userctl peer list`. An operator
  path is mandatory, not optional -- rule 1 will eventually fire on something we
  did not predict. See also the known-good exemption below, which is the
  automatic half of the same concern.

### The known-good exemption

An address that has recently completed a **successful authentication by a real
account** is exempt from connection-level bans.

The purpose is to bound the denial-of-service exposure of rule 1. Rule 1 bans on
a single attempt against a nonexistent account, which is what makes it effective
against the measured spray -- but it also means one hostile connection from a
shared address can lock out a legitimate user behind it. Recording who has
actually authenticated gives the policy a reason to prefer the user.

Only real accounts can produce this mark. A successful authentication *is* proof
the account exists, and inbound SMTP never authenticates, so mail reception
cannot mark an address good. Submission does, correctly -- that is a real user.

Three bounds, because an exemption keyed on holding a valid credential is
otherwise an attacker's asset:

1. **It exempts the connection ban only, never the authentication rate
   limiter.** A stolen credential buys connectivity from that address, not
   unlimited password guessing: rule 2's counters still apply per (IP, user).
   The two mechanisms live in different packages and nothing wires them
   together; `TestKnownGood_DoesNotExemptTheRateLimiter` keeps it that way.
2. **Revocation.** Each suppressed ban is counted, and past `revoke_after`
   (default 10) the known-good marker is deleted and bans apply normally. An
   address that keeps earning bans stops being trusted however many real logins
   it has.
3. **The ban itself is not deleted**, only ignored. It stays on record, keeps
   its TTL, and still appears in `userctl peer list`, so what policy decided
   stays visible even while the exemption overrides it.

**Measurement is the point**, since the tradeoff cannot be settled from first
principles. `userctl peer good` reports, per address, successful logins against
bans suppressed. An address with a nonzero suppressed count is carrying both a
real user and hostile traffic -- exactly the case that needs an operator's
judgement rather than a default. Suppressions also log at warn.

Two ordering properties worth knowing:

- **A banned address can never become known-good.** The gate closes the
  connection before any protocol runs, so it can never authenticate to prove
  itself. Known-good status is only ever established *before* a ban, never as a
  way out of one; operator recovery for a wrongly banned address is
  `userctl peer unban`. This is also why `good_ttl` defaults to 30 days and
  slides on every success -- a short window would expire the exemption exactly
  when a spray from a recycled address needs it.
- **The exemption lookup costs nothing on the happy path.** It runs only after
  a ban has been found, so an unbanned peer still costs exactly one Redis
  lookup.

### Ban scope: where the evidence came from decides where it applies

A ban is enforced on the listeners its evidence speaks to, not on every port
(#225).

Rule 1's justification is narrow and airtight: *no legitimate client
authenticates as an account that does not exist.* Extending it to inbound SMTP
requires a different and much weaker claim -- *no legitimate MTA sends from an
address that once did* -- which nothing in the data supports. The costs are
asymmetric in kind, not degree: refusing a sprayer's IMAP attempt costs nobody
anything, while refusing inbound SMTP destroys a third party's message. And the
measured spray came from DigitalOcean, Tencent, Scaleway and GoDaddy, which is
exactly the shared infrastructure where a sprayer and a real sending MTA
plausibly share an address.

So:

| Ban reason | auth-facing listeners (imap, pop3, submission, smtps) | inbound SMTP (25) |
|---|---|---|
| `nonexistent_account` (rule 1) | enforced | **shadow: served and recorded** |
| `abuse:<signal>` (rule 3) | enforced | enforced |
| `manual` (operator) | enforced | enforced |
| anything unclassified | enforced | enforced |

Rule 3 enforces everywhere because its evidence is SMTP-native -- the address
demonstrated the behaviour on the port being refused -- and no legitimate IMAP
client sits behind an address probing for an open relay. Operator bans enforce
everywhere because someone meant it. An unclassified reason enforces everywhere
so that adding a ban source cannot silently stop protecting something.

**Shadow mode is a measurement, not a permanent state.** A shadow-banned
connection is served, logged at warn with the address, and counted as
`peer_gate_checks_total{verdict="shadow"}`, so the volume of would-be refusals
can be cross-referenced against the mail that actually arrived. Set
`auth_ban_scope = "all"` once the data says the refusals cost nothing.

Two smaller points that argue the same way, and that shadow mode also defers:

- **A silent close is a bad SMTP citizen.** The gate holds ~30s and closes with
  no banner and no status code, which a legitimate MTA reads as a network fault:
  it queues, retries for days, then bounces something confusing, and the
  recipient never learns the message existed. Enforcing on 25 should probably
  mean a `421` after the banner rather than a silent hold. Greylisting is this
  same idea done properly, because it speaks SMTP.
- **SMTP already has better-calibrated defences.** RBLs, greylisting, SPF/DKIM/
  DMARC and rspamd are tuned with global visibility. A ban inferred from an IMAP
  authentication attempt is a worse predictor of "this MTA sends spam" than
  Spamhaus is, and the gate stacks it in front of all of them where nothing can
  override it.

There is also a small griefing vector: someone on shared hosting can spray
authentication deliberately to get the shared address banned, denying mail
service to innocent co-tenants' outbound. Our ban, their weapon.

### Rule 2: wrong password on a real account -> graduated counter

The rare case in the data, and the only one where a false positive locks out a
real person. It keeps the conservative behavior of today's limiter, minus the
dimension that is a DoS vector.

- Keys: `auth:fail:ipuser:<ip>|<user>` and `auth:fail:ip:<ip>`, sliding window
  via Redis TTL, lockout written as `auth:lock:...` with the lockout TTL.
- **The username-only dimension is dropped.** `MaxFailuresPerUser` in
  `auth/domain.RateLimitConfig` lets an attacker distributed across 59 IPs lock
  out a real account for the price of ten requests. It is removed as an
  enforcement dimension; if the aggregate is wanted for alerting it can be a
  metric, and only a metric.
- No ban here, only lockout. Wrong-password-on-a-real-account is what a
  legitimate user with a stale saved password looks like.

### Rule 3: unauthenticated smtpd abuse -> per-IP volumetric counters

Ordinary volumetric limits, in their own keyspace
(`smtpd:abuse:ip:<ip>:<signal>`), for behavior that never reaches an auth
attempt: invalid-recipient rate, connection and reconnect rate, early talkers,
malformed commands, aborted DATA, and per-IP message/recipient volume (distinct
from the existing per-*sender* limiter in `internal/smtpd/smtp/ratelimit.go`).

Implemented so far: `invalid_recipient` and `relay_denied` (phase 5, enforcing),
`connection_rate` and `unhosted_domain` (#221, counted only). Still unbuilt:
`early_talker`, `malformed_command` and `data_abort`, all three blocked on a
go-smtp hook or an MSG_PEEK prototype rather than on a call site -- they keep
reserved names in `internal/peersignal` so a threshold configured for them is not
silently orphaned.

Per-IP thresholds are the right model *here*, unlike rule 1: a real inbound
peer's traffic is attributable to its IP, and legitimate MTAs do not probe
recipients. Greylisting is the precedent -- same Redis, same abstraction,
different keyspace and thresholds. Exceeding a rule-3 threshold produces a ban
(feeding rule 1's keyspace) rather than a per-signal lockout, because the
enforcement point is the same accept-time gate.

A signal with no entry in `abuse_thresholds` is counted and never bans. That is
not a degenerate case, it is how a new signal ships: counted first, enforced only
once production data says where the threshold belongs. `userctl peer abuse` is
where those counts are read, and it prints the configured threshold beside each
one so "measured, not yet enforced" is distinguishable from "broken".

#### `connection_rate`: reconnect storms

The highest-value signal the original design listed and phase 5 could not build,
because it needs a mechanism rather than a call site. Shipped in #221 counted
only.

The measured data is what motivates it: **446 smtpd connections against 64 auth
attempts, and 2165 imapd connections against 619 auth attempts** in 24h. Most
abusive connections never authenticate and never reach RCPT, so neither
`invalid_recipient` nor `relay_denied` ever sees them.

**Where it is counted, and why not elsewhere.** In `peergate.Gate.CheckPeer`,
after the allowlist and *before* the verdict cache lookup. Three facts pin that
placement:

- `CheckPeer` is called once per accepted connection by `connfork.spawnHandler`,
  and the 10s/60s verdict cache sits *inside* it. So the cache hides accepts from
  session-manager but not from here. A counter behind the cache -- or any count
  derived from `CheckPeer` RPCs arriving at session-manager -- undercounts a flood
  by exactly the factor that matters.
- The allowlist lives in `peergate` and only there. A counter in `connfork` could
  not skip the operator's own networks without duplicating it, and a monitoring
  check hammering the management network is exactly what a storm looks like.
- `connfork` is deliberately policy-agnostic (`Mode` is opaque to it), while this
  package's stated job is already "how cheaply is the question answered". A local
  rate detector is the same class of thing as the verdict cache.

Keyed by `(address, listener role)`, reusing `cacheKey`. A submission storm and an
inbound-25 storm are different phenomena with different legitimacy, and smtpd
serves both from one process -- #225 already showed what unkeyed state shared
across roles does there.

**Reporting is once per window per key.** A sustained flood is one `ReportPeer`
per window, not one per accept past the threshold, or the signal becomes the load
it exists to describe. An already-denied peer is counted but **not** reported: no
RPC is worth spending on an address whose connections are already being refused,
and once the signal does have a ban threshold, reporting there would make the ban
self-renewing -- each ban window's reconnect storm would re-cross and re-ban,
turning a 24h ban into a permanent one. The suppression is visible as
`peer_conn_rate_exceeded_total{result="suppressed_banned"}`, so the traffic is
never invisible.

**Two semantics to state before anyone sets a threshold**, because both are
surprising:

- The Redis counter counts *local crossings*, not connections. A future
  `connection_rate = 5` means five local-window crossings inside `abuse_window`,
  which is roughly `5 x connection_rate_threshold` connections, not five.
- All three daemons report the same signal name into one per-address key, so a
  threshold is met by the **sum** across smtpd, imapd and pop3d, and across roles
  within smtpd. That is arguably right -- the measured attack sprayed several
  daemons -- but the effective per-daemon rate is a fraction of the number written
  in the config.

**Blocker on enforcement, recorded here rather than discovered later.** `Report`
bans with reason `abuse:<signal>`, and `isAuthDerived` is a plain map lookup on
the stored reason where unknown reasons fail toward strict. So an
`abuse:connection_rate` ban would be enforced on port 25 -- refusing a legitimate
busy MTA's mail, which is precisely the harm `auth_ban_scope` exists to prevent.
Unreachable while the signal has no threshold; **mandatory to fix before giving it
one**, and it needs `isAuthDerived` to understand the `abuse:` prefix rather than
matching whole strings.

#### `unhosted_domain`: an auth attempt for a domain we do not host

The authentication-side twin of `invalid_recipient`, and counted for the same
reason. Added in #221 to fix a live false positive rather than to add coverage.

Before it, this case had no representation at all, and what happened depended on
deployment accident. `AuthRouter.authenticateInternal` found no hosted domain and
fell through to the fallback agent; production configures one
(`manager.SetupAuth`), the fallback missed, and the attempt came back
`ErrUserNotFound` -- indistinguishable from rule 1's real case, so the address was
banned on the first attempt. Every test fixture passed a nil fallback, where the
same attempt returned `ErrAuthFailed` and nothing happened. Production and the
tests disagreed about what the case was, which is why nothing caught it.

The cost was not hypothetical: a domain migrated off this server would have had
its former users' addresses banned as their stale clients retried. That is
precisely the population a migration is trying not to break, which is why this
counts rather than bans, and why it ships with **no default threshold**.

`auth/errors.ErrDomainNotHosted` now carries the distinction, returned when
`GetDomain` misses **and the provider hosts domains at all**. The second
condition matters: the fallback agent exists for the legacy unqualified case --
old unix `user@host`, where the host is implied -- so a server with no domains
configured is exactly that host and keeps its behaviour unchanged, while a server
with domains is not, and a qualified username naming an unhosted domain never
reaches its fallback. `auth/passwd` keys its user map on the exact string from
the passwd file, so a literal `user@legacy.example` entry is a real supported
configuration on such a host; short-circuiting before the fallback
unconditionally would have broken it.

Two consequences worth stating rather than discovering later:

- `hasDomains()` costs a directory scan for the filesystem provider, so it is
  checked last -- only an attempt that has already named an unhosted domain pays
  for it, and that path is held for `auth_fail_delay` regardless.
- Reclassifying before the fallback means this path skips `auth/passwd`'s decoy
  argon2id verify and returns in microseconds. The absolute `auth_fail_delay`
  deadline is what hides that, and with `auth_fail_delay = "0s"` the asymmetry is
  exposed. See the residual-oracle discussion.

RFC note, since it looks adjacent and is not: RFC 5321 §2.3.5 does require
accepting `RCPT TO:<Postmaster>` **without domain qualification**. That is a
recipient-path mandate, not an authentication one -- RFC 4954 and RFC 4422 leave
the SASL authorization identity opaque and application-specific, so nothing
requires authenticating an unqualified or unhosted username. The RCPT side is
tracked separately in #230.

## Response timing and the enumeration oracle

The daemons already log `authentication failed: user not found` server-side
while returning an undifferentiated failure to the client. Rule 1 makes the
nonexistent-account path *behave* differently, so timing has to be handled
deliberately or the limiter becomes the enumeration oracle the current code
avoids.

### On the auth path: one uniform delay, as an absolute deadline

Every failed `Login` response is released at a fixed offset **D** from a fixed
reference point (receipt of the credentials), regardless of why it failed and
regardless of how long the work took. An absolute deadline, not `sleep(D)` after
the work: additive sleep leaves the argon2id verify time visible in the total,
and the nonexistent-account path does not run argon2id at all. That difference
is measurable, which is the whole reason the deadline has to be absolute.

Where a nonexistent account is detected before any password hashing happens, the
handler must still consume the deadline -- and should perform a dummy argon2id
verify against a fixed decoy hash, so that CPU and timing profiles match as well
as wall-clock does.

**D = 5s, not 30s** (decided 2026-07-24). The reasoning:

- 30s exceeds or brushes the idle/response timeout of several common IMAP
  clients. A real user who typos their password would get "connection timed out"
  instead of "authentication failed", which is a worse outcome for them and a
  support burden for us -- and unlike the attacker, they will retry.
- The deterrent against the spray is the **ban**, not the delay on the
  connection where the signal was observed. The sprayer makes one attempt per IP
  and does not care how long the reply takes; delaying it 30s instead of 5s buys
  nothing against the measured attack.
- 5s still costs a serial bruteforcer real throughput and is invisible to a
  human typing a password wrong.

### At accept time: this is where 30s belongs

An already-banned IP has no legitimate client behind it and nothing left to
learn, so hold it. **Default accept-time tarpit: 30s**, subject to `MaxTarpit`.
This is the tarpit that does useful work -- it consumes attacker connection
slots for the price of one fd, and it does it before we spend a fork, a
handshake, or a hash.

The connection is held silently and then closed without a protocol error.
Sending a banner or an error first tells a scanner it reached a live service;
closing after a silent hold is indistinguishable from a blackhole route.

### The residual oracle, stated plainly

Rule 1 creates a weaker second-order oracle that the issue does not note, and
the design should not pretend otherwise. An attacker can test whether account X
exists: attempt X from a fresh IP, then reconnect from that same IP. Tarpitted
means X did not exist. Not tarpitted means it did.

The cost to the attacker is one burned source address and two connections per
username tested, for one bit. That is far worse than the fast oracle we are
avoiding, and it is self-limiting -- probing burns exactly the resource the ban
is designed to consume. The recommendation is to **accept this and document it**,
because the alternative is giving up the N=1 rule that is the only thing that
catches the measured attack.

If it later needs closing, the mitigation is to make a ban ambiguous rather than
to weaken rule 1: also ban after 2 wrong-password failures on a real account, so
"banned" no longer implies "nonexistent". That trades rule 2's conservatism for
oracle resistance and should be a config knob (`ban_on_password_failures`,
default off), not a silent default.

## Fail open or closed

Per rule, because the tradeoffs point in opposite directions:

| Path | Redis/session-manager error | Why |
|---|---|---|
| Accept-time gate (rule 1) | **fail open** | A session-manager outage must not become a total mail outage. Failing closed here refuses every connection on every daemon. |
| Auth lockout (rule 2) | **fail open** | Matches the existing sender limiter. Failing closed locks out legitimate users during an outage, which is the same damage the attacker wants. |
| smtpd abuse counters (rule 3) | **fail open** | Volumetric limits on inbound mail; blocking mail is worse. |

Fail-open everywhere, but **loudly**: a counter
(`peer_gate_checks_total{verdict="error"}`) and an error log on every gate failure, plus
an alert rule on a sustained nonzero rate. A silent fail-open is a protection
mechanism that can be switched off by breaking Redis, and nobody would notice.

`strict_gate = false` in config allows an operator to invert the accept-time gate
to fail closed. It stays off by default; a deployment that would rather be down
than unprotected can say so.

## Redis keyspace

| Key | Type | TTL | Written by |
|---|---|---|---|
| `peer:ban:<prefix>` | string (policy label) | 24h / 7d | session-manager |
| `peer:strikes:<prefix>` | counter | 30d | session-manager |
| `auth:fail:ipuser:<ip>\|<user>` | counter | window | session-manager |
| `auth:fail:ip:<ip>` | counter | window | session-manager |
| `auth:lock:ipuser:<ip>\|<user>` | string | lockout | session-manager |
| `auth:lock:ip:<ip>` | string | lockout | session-manager |
| `smtpd:abuse:ip:<ip>:<signal>` | counter | window | session-manager |

Every key is written by session-manager only; the daemons never touch Redis for
this. INCR plus conditional EXPIRE on first write, following
`internal/smtpd/smtp/ratelimit.go`.

**Redis TTL replaces the 5-minute sweep goroutine** in
`auth/domain/ratelimit.go` (`cleanup`, and the `failureBucket` pruning it
exists to do). That is a net deletion.

## What changes in auth/domain/ratelimit.go

The call-site API (`isLimited` / `recordFailure` / `recordSuccess`) keeps its
shape; the backing store goes behind an interface:

```go
type limitStore interface {
    incr(ctx context.Context, key string, window time.Duration) (int64, error)
    get(ctx context.Context, key string) (string, bool, error)
    set(ctx context.Context, key, val string, ttl time.Duration) error
    del(ctx context.Context, keys ...string) error
}
```

with a `redisLimitStore` and the existing map-based implementation retained as
`memLimitStore` -- the test double, and the fallback when Redis is not
configured. `MaxFailuresPerUser` and the `user` map are deleted (see rule 2).

## Metrics

New, all domain- or IP-class-level, never per-user. Two families: the
dispatcher-owned `<daemon>_peer_*` series record what was *done* with a verdict,
and the `session_manager_peer_*` series record what was *decided*.

- `<daemon>_peer_gate_checks_total{verdict}` -- verdict in allow/deny/error.
- `<daemon>_peer_gate_cache_total{result}` -- hit/miss. Note this is not a
  load-shedding measure: the cache exists so the three daemons agree on a shared
  ban, and a low hit rate against spray traffic is expected rather than a fault.
- `session_manager_peer_bans_total{reason}` -- bans created, by reason class.
  Rule-3 bans are stored as `abuse:<signal>` and collapse to `abuse` here,
  because the stored reason is unbounded as a label value; the per-signal
  breakdown is `peer_abuse_signals_total`. An unrecognized reason lands in
  `other` rather than growing the label set (#228).
- `session_manager_peer_ban_strikes_total{strikes}` -- bans by offense count on
  record, bucketed `1`/`2`/`3+`. Anything at 2 or above served the escalated TTL,
  so this is how to tell whether the escalation is doing anything.
- `session_manager_peer_abuse_signals_total{signal}` -- every rule-3 signal
  recorded, whether or not it reached a threshold. This is the only place a
  *shadowed* signal is visible: one with no configured threshold never bans, so
  it appears in no ban listing and logs nothing. Without it, "never fired" and
  "never ran" are the same observation.
- `session_manager_peer_known_good_total`, `..._peer_ban_suppressed_total`,
  `..._peer_known_good_revoked_total`, `..._peer_unbans_total` -- the known-good
  exemption's rates and operator unbans.
- Deliberately **no** counter for `Check` verdicts on the session-manager side.
  Every dispatcher already reports one, and a second family counting the same
  event would be two numbers that disagree the moment either has a bug.
- Known-good suppressions and abuse counts are *also* held per address in Redis
  and surfaced by `userctl peer good` and `userctl peer abuse`, because the
  useful question there is "which addresses" rather than "how many" -- a rate
  tells you nothing about whether to intervene.
- `<daemon>_peer_conn_rate_exceeded_total{result}` -- local connection-rate
  threshold crossings, `reported` or `suppressed_banned`. With the signal
  unenforced this and `peer_abuse_signals_total{signal="connection_rate"}` are the
  whole dataset for deciding whether it ever should be.
- `peer_tarpit_active` -- gauge; watch it against `MaxTarpit`.
- `peer_tarpit_rejected_total` -- denied connections closed immediately because
  the tarpit budget was full. Nonzero means `MaxTarpit` is undersized.
- `peer_gate_checks_total{verdict="shadow"}` -- would-be refusals on inbound
  SMTP, the dataset for deciding whether to widen auth-derived bans (#225).
- Gate errors are the `verdict="error"` label on `peer_gate_checks_total` rather
  than a separate family -- one series answers "how often is the gate
  consulted, and how does it come out", and the fail-open alarm is a nonzero
  rate on that label.

Fix #207 before relying on any of this. A registered-but-never-incremented
metric reads as zero rather than as absent, and this design adds six more
places for that to happen.

## Configuration

As implemented. The policy half lives under `[session-manager]`; the dispatcher
half is one shared top-level `[peergate]` section that all three daemons read
from a single struct definition, the same way they share `[redis]` and
`[session-manager]`.

**Everything below is the default.** An empty config file behaves exactly like
this, so the block is documentation rather than something a deployment has to
write. `enabled` is the only field with a tri-state: absent means on, and an
explicit `false` is distinguishable from an absent key.

```toml
# Policy: what gets banned, and for how long.
[session-manager]
auth_fail_delay = "5s"         # uniform deadline for ALL auth failures; "0s" disables

[session-manager.redis]
url = "redis://redis:6379/1"   # required; without it neither feature enforces

[session-manager.ratelimit]
enabled = true
max_failures_per_ip_user = 5
max_failures_per_ip = 20
window = "5m"
lockout = "15m"
# No per-username threshold, deliberately: see rule 2.

[session-manager.peerfilter]
enabled = true
allowlist = ["127.0.0.0/8", "::1/128"]
ban_ttl = "24h"
ban_ttl_repeat = "168h"       # set equal to ban_ttl to disable escalation
accept_tarpit = "30s"
abuse_window = "1h"
auth_ban_scope = "auth_listeners"  # "all" also refuses inbound SMTP on 25
known_good = true             # exempt addresses with a recent successful login
good_ttl = "720h"             # 30 days, refreshed on every success
revoke_after = 10             # suppressed bans before trust is withdrawn; -1 never

[session-manager.peerfilter.abuse_thresholds]
# Signals with no entry here are counted but never ban on their own. An absent
# table takes these defaults; a table you write is used verbatim, so omitting a
# signal is how you turn it off.
invalid_recipient = 10        # a dictionary, not a typo
relay_denied = 5              # nothing legitimate probes for an open relay
# unhosted_domain has deliberately no entry: a stale client left pointed at a
# migrated domain looks exactly like this, so it is counted and never bans until
# production data says where a threshold belongs. Read the counts with
# `userctl peer abuse` (#221).

# Enforcement: how the dispatchers act on that policy.
[peergate]
enabled = true
allowlist = ["127.0.0.0/8", "::1/128"]
gate_timeout = "2s"
max_tarpit = 256              # negative: enforce bans, hold nothing
strict_gate = false           # true: deny when the gate is unreachable
allow_ttl = "10s"
deny_ttl = "60s"
cache_size = 8192
connection_rate_threshold = 60  # accepts per window per (address, listener role);
                                # negative disables. Crossing it reports the
                                # connection_rate signal, which has no ban
                                # threshold, so nothing is refused (#221).
connection_rate_window = "1m"
```

Two allowlists, on purpose. The `[peergate]` one is checked in the dispatcher
before any RPC, so an allowlisted peer costs nothing; the
`[session-manager.peerfilter]` one is what refuses to *record* a ban. Keeping
both means neither a dispatcher bug nor a policy bug alone can lock an operator
out. They should normally hold the same CIDRs.

`ban_on_password_failures` is the only knob still outstanding; see the residual
oracle discussion.

## Test plan

TDD; the first three are the ones that matter, and the timing test is the one
that must not be skipped.

1. **Timing indistinguishability.** Nonexistent account and wrong-password on a
   real account, measured end to end over many trials: response text identical,
   and the response-time distributions statistically indistinguishable. Assert
   on the spread of both, not on a single sample -- a single measurement passes
   trivially and proves nothing. This is the test the issue asks for explicitly.
   *(Done: `TestLogin_FailureTimingIsIndistinguishable`, with
   `TestLogin_TimingLeaksWithoutTheDeadline` as its control, plus
   `TestAuthenticate_UnknownUserCostsLikeWrongPassword` at the auth layer.)*
2. **Rule 1 fires on N=1.** One nonexistent-account `Login` produces a ban; the
   next connection from that IP to a *different* daemon is denied at accept
   time. Cross-daemon is the point -- it is the whole argument for Redis.
   *(Done: `TestLogin_NonexistentAccountBansOnFirstAttempt` for the ban,
   `TestRedisLimitStore_LimiterEndToEnd` for the cross-process sharing.)*
3. **Tarpit does not starve handlers.** Fill `MaxTarpit` with denied
   connections, then assert an allowed connection still gets a handler token
   promptly. This is the self-DoS regression test. *(Done:
   `TestGate_TarpitDoesNotStarveHandlers`.)*
4. **Fail-open on gate error.** Kill Redis, kill session-manager: connections
   still served and the error verdict is counted. Then with
   `strict_gate = true`: connections refused. *(Done:
   `TestGate_ErrorFailsOpen`, `TestGate_ErrorFailsClosedWhenStrict`,
   `TestGate_TimeoutIsAGateError`, `TestCheck_FailsOpenOnRedisError`. The
   counter is `peer_gate_checks_total{verdict="error"}` rather than a separate
   family.)*
5. **Allowlist wins over an active ban**, and generates no RPC. *(Done:
   `TestCheckPeer_AllowlistCostsNoRPC`, `TestAllowlist_NeverBannedNeverChecked`.)*
6. **Cache TTL asymmetry**, using an injected clock: a deny is reused for 60s, an
   allow re-checked after 10s. *(Done: `TestCheckPeer_CacheTTLAsymmetry`.)*
7. **IPv6 /64 normalization** -- a ban earned by one address in a /64 denies a
   sibling address.
8. **Unban** clears the ban and the strike counter, and takes effect within one
   cache TTL.
9. **`PeerGate` nil** preserves current dispatcher behavior exactly (the
   existing connfork suite, unmodified). *(Done: `TestGate_NilGateSpawnsHandler`,
   plus the unmodified suite.)*
10. Rule 2 lockout thresholds and window expiry against `memLimitStore` with an
    injected clock; rule 3 counters likewise. *(Done: the `auth/domain` suite for
    rule 2, `TestReport_*` and the `rule3_test.go` suite for rule 3.)*

## Phasing

Each phase is separately shippable and separately reviewable.

1. `limitStore` interface plus `redisLimitStore` behind the existing
   `auth/domain` API; drop the username dimension; delete the sweep goroutine.
   No behavior change for the daemons. **Done.**
2. **Wire the limiter up at all** (see below), then `CheckPeer`/`ReportPeer` on
   `SessionService`; policy and Redis in session-manager; `userctl peer
   list|unban`. **Done.**
3. `PeerGate` in connfork, with the token accounting, tarpit budget, allowlist,
   and parent cache. Wire all three dispatchers. **Done.**
4. Rule 1 recording on the `Login` path plus the uniform failure deadline and
   the decoy verify. **Done.**
5. Rule 3 counters in smtpd, via `ValidateRecipient` and `ReportPeer`.
   **Partly done** -- `invalid_recipient` and `relay_denied` ship; the
   connection-rate, early-talker, and malformed-command signals need mechanisms
   that do not exist yet and are tracked in #221.

Phase 3 lands the enforcement, so nothing before it changes what a client sees;
phase 4 is where the timing test becomes mandatory.

### The limiter is not wired up, and phase 2 has to fix that first

**Resolved in phase 2.** `LoginRequest` carries `client_ip`, every daemon sends
it, session-manager calls `WithRedisRateLimit`, and
`TestLogin_ClientIPReachesRateLimiter` asserts the whole chain. The rest of this
section is kept as the record of what was wrong.

Found while implementing phase 1. The issue describes the existing limiter as
losing its state on restart, which is true but understates the situation:

- `session-manager/manager/manager.go` builds the `AuthRouter` with
  `domain.NewAuthRouter(...)` and **never calls `WithRateLimit`**, so
  `rateLimiter` is nil and every check, record, and reset is skipped.
- **Nothing anywhere calls `WithClientIP`.** Even with the limiter enabled,
  every IP-keyed dimension would see `""`.

Together those mean there has never been any authentication rate limiting in
production, and that the only dimension that could have fired is the
username-keyed one that phase 1 removed as a DoS vector. So the >99%-hostile
traffic in the measured window met no limiter at all.

Two consequences for phase 2, both required before any of this does anything:

1. **`LoginRequest` needs a `client_ip` field.** The daemons know the peer
   address; session-manager, which performs the authentication, currently has no
   way to learn it. Without that field the limiter cannot key on anything, and
   `WithClientIP` has no value to carry. This also gives rule 1 the address it
   needs to ban.
2. **session-manager must call `WithRedisRateLimit`** and set the client IP on
   the context around `AuthenticateWithDomain`.

Note that this makes phase 2 the first point where a real user can be locked
out, which is worth remembering when picking the initial thresholds: they will
be applied to production traffic that has never had them before.

### Decided during phase 5

- **`invalid_recipient` is recorded in `ValidateRecipient`, not reported by
  smtpd.** session-manager already knows whether the recipient exists, so the
  signal costs one line where the answer is computed rather than a round trip
  from the daemon. Only `client_ip` had to be added to the request.
- **A nonexistent *domain* is not counted.** That is misdirected mail, not
  probing of our address space, and counting it would ban anyone whose
  forwarding is misconfigured.
- **Rule 3 is a rate, not a first-attempt ban** -- the opposite of rule 1. A
  nonexistent *account* on the auth path is proof of hostility; a nonexistent
  *recipient* is what writing to a retired address looks like, and real MTAs
  retry.
- **Signal names live in a dependency-free `internal/peersignal`.** They cross
  the wire and appear as config keys, so they are a compatibility surface:
  renaming one silently orphans an operator's threshold. The names for the
  unimplemented signals are reserved there for the same reason.
- **Default thresholds ship set**, so rule 3 enforces unconfigured. An absent
  table takes the defaults; a table the operator wrote is used verbatim,
  including an empty one, because omitting a signal is how you disable it.
- **Connection-rate counting cannot live in `CheckPeer`.** The phase 3 verdict
  cache means session-manager sees roughly one check per address per 10s, not
  one per connection, so any count derived there undercounts a flood by exactly
  the factor that matters. It needs local counting in the dispatcher with
  central policy -- see #221.

### Decided during phase 4

- **The decoy verify lives in `auth/passwd`, not in the router.** The agent owns
  the hash format and parameters, so it is the only place that can produce a
  decoy costing exactly what a real verify costs. Measured gap being closed:
  1.6us versus 26.6ms.
- **The deadline lives in session-manager's `Login`, not in each daemon.** It is
  the single funnel all three protocols pass through, and the daemons return as
  soon as the RPC does, so the RPC duration is the client-visible duration.
- **The deadline covers rate-limited responses too.** Not because a lockout
  reveals account existence -- it does not -- but because one uniform rule is
  easier to keep correct than a set of exceptions, and delaying a locked-out
  attacker costs them rather than us.
- **Rule 1 does not fire on a wrong password**, only on a nonexistent account.
  Wrong-password-on-a-real-account is what a stale saved password looks like and
  stays with rule 2, where a false positive costs a lockout rather than a ban.
- **The timing test ships with a control.** A test that asserts two
  distributions are close passes just as happily when neither has any signal in
  it. `TestLogin_TimingLeaksWithoutTheDeadline` asserts the asymmetry *is*
  observable with the deadline off, so the real test cannot rot into a no-op.

### Decided during phase 3

- **Secure by default, reversing phase 2's opt-in.** Absent configuration
  enables the peer filter, the auth limiter, and the dispatcher gate.
  `enabled` became `*bool` in each so an absent key stays distinguishable from
  an explicit `false` -- with a plain bool the zero value is `false`, which is
  backwards for a security control. Defaulting on is safe where it would
  otherwise surprise: with no Redis the filter is off entirely and the limiter
  falls back to per-process counters, so a deployment without Redis sees no
  change.
- **Cache eviction is generational, not LRU.** When the live map fills it
  becomes the previous generation and a fresh map takes over: lookups check two
  maps, inserts stay O(1), and the cache is bounded at twice its configured
  size. Scanning for the oldest entry would be O(n) per insert exactly when the
  cache is full, which under a spray is always. An entry survives one roll;
  two may drop it, which costs an extra RPC rather than a wrong answer.
- **Two allowlists, dispatcher and policy.** The dispatcher's is checked before
  any RPC (so an allowlisted peer costs nothing); the policy one refuses to
  record a ban. Neither a dispatcher bug nor a policy bug alone can lock the
  operator out.
- **The gate call holds a handler token while it runs.** `acceptLoop` acquires
  before `Accept` by design, so a denied connection occupies a handler slot
  until its check resolves -- bounded by `GateTimeout`, normally a cache hit.
  Checking before acquiring would mean accepting connections with no slot for
  them.
- **smtpd gets no `MaxConns`.** It has never had a connection limit and
  inventing one here would be an unrelated behavior change. The tarpit budget
  is independent of it.

### Decided during phase 2

- **Graduated ban TTL: implemented, and disableable.** A strike counter with a
  30-day TTL (longer than the longest ban, so an address that serves a full ban
  and returns is still recognized) selects `ban_ttl_repeat` over `ban_ttl`.
  Setting the two equal turns escalation off without a separate flag.
- **The peer filter requires Redis; the auth limiter does not.** The auth
  limiter keeps its in-process fallback because a bruteforcer hammering one
  connection is visible to whichever process holds it. An accept-time ban has no
  per-process meaning at all -- separate daemons, one-shot handlers, and an
  attack that sprays several daemons from the same addresses -- so with no Redis
  the filter is off rather than pretending to work.
- **Both features default to off.** They are the first authentication limits
  this deployment has ever enforced, so enabling them is an explicit operator
  decision rather than something an upgrade does silently.
- **`userctl peer` also has `ban`.** `list` and `unban` were the requirement;
  manual `ban` came free from the same policy object and gives an operator a way
  to act on something they have spotted themselves.

## Left to decide

- Whether `ban_on_password_failures` ships as a knob or waits until the residual
  oracle is shown to matter. Still deferred: nothing has been observed exercising
  the oracle, and it costs an attacker one address per username tested.
- **Initial production thresholds.** Nothing has ever been enforced here, so
  there is no baseline for how often a real client fails a login, writes to a
  retired address, or trips any rule 3 signal. Every default in this document is
  an inherited guess, not a measurement. Worth watching the first week and then
  tightening.

  The instrumentation to watch, in order of what would show a false positive
  first: `userctl peer list` (what is being banned and why),
  `userctl peer abuse` (rule-3 counters per address and signal, with the
  configured threshold beside each count -- a counter climbing against a
  threshold of `none` is a signal being measured before anyone decided to
  enforce it, which is not the same as a signal that is broken),
  `userctl peer good` (addresses carrying both a real user and hostile traffic
  -- a nonzero suppressed count is the exemption earning its keep),
  `<daemon>_peer_gate_checks_total{verdict="deny"}` (how much is being refused
  at accept time), and `<daemon>_peer_tarpit_rejected_total` (nonzero means
  `max_tarpit` is undersized).

  The knobs to reach for, from least to most drastic: raise the specific
  threshold; `revoke_after = -1` to trust known-good addresses
  unconditionally; `known_good = false` if the exemption turns out to cost more
  than it buys; `peerfilter.enabled = false` to stop enforcing while keeping the
  counters. `userctl peer unban` handles the individual case without changing
  policy at all.
