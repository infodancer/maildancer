# Hostile connection filtering

Design for issue #206 (Redis-backed auth rate limiting and connection-level
banning). Status: phases 1-3 implemented; phases 4-5 outstanding (see Phasing).
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
  did not predict.

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

Per-IP thresholds are the right model *here*, unlike rule 1: a real inbound
peer's traffic is attributable to its IP, and legitimate MTAs do not probe
recipients. Greylisting is the precedent -- same Redis, same abstraction,
different keyspace and thresholds. Exceeding a rule-3 threshold produces a ban
(feeding rule 1's keyspace) rather than a per-signal lockout, because the
enforcement point is the same accept-time gate.

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

New, all domain- or IP-class-level, never per-user:

- `peer_gate_checks_total{daemon,verdict}` -- verdict in allow/deny/error.
- `peer_gate_cache_total{daemon,result}` -- hit/miss, to confirm the cache
  actually absorbs storms.
- `peer_bans_total{rule}` -- bans created, by which rule fired.
- `peer_tarpit_active` -- gauge; watch it against `MaxTarpit`.
- `peer_tarpit_rejected_total` -- denied connections closed immediately because
  the tarpit budget was full. Nonzero means `MaxTarpit` is undersized.
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

[session-manager.peerfilter.abuse_thresholds]
# Signals with no entry here are counted but never ban on their own.
# Populated in phase 5, when smtpd starts reporting them.

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
```

Two allowlists, on purpose. The `[peergate]` one is checked in the dispatcher
before any RPC, so an allowlisted peer costs nothing; the
`[session-manager.peerfilter]` one is what refuses to *record* a ban. Keeping
both means neither a dispatcher bug nor a policy bug alone can lock an operator
out. They should normally hold the same CIDRs.

Still to come: `auth_fail_delay = "5s"` and `ban_on_password_failures` arrive
with phase 4, which is where the auth-path timing work lands.

## Test plan

TDD; the first three are the ones that matter, and the timing test is the one
that must not be skipped.

1. **Timing indistinguishability.** Nonexistent account and wrong-password on a
   real account, measured end to end over many trials: response text identical,
   and the response-time distributions statistically indistinguishable. Assert
   on the spread of both, not on a single sample -- a single measurement passes
   trivially and proves nothing. This is the test the issue asks for explicitly.
2. **Rule 1 fires on N=1.** One nonexistent-account `Login` produces a ban; the
   next connection from that IP to a *different* daemon is denied at accept
   time. Cross-daemon is the point -- it is the whole argument for Redis.
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
    injected clock; rule 3 counters likewise.

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
   the decoy verify.
5. Rule 3 counters in smtpd, via `ValidateRecipient` and `ReportPeer`.

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

- Whether `ban_on_password_failures` ships as a knob in phase 4 or waits until
  the residual oracle is shown to matter.
- **Initial production thresholds.** Nothing has ever been enforced here, so
  there is no baseline for how often a real client fails a login. The defaults
  (5 per pair, 20 per address, 5-minute window, 15-minute lockout) are inherited
  guesses, not measurements. Worth watching the first week with
  `peerfilter.enabled` on and the auth limiter's thresholds set high, then
  tightening.
