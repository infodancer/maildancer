# smtpd cross-process metrics aggregation

Status: design + implementation (decided, shipped). Written 2026-07-24 alongside
the fix for GitHub issue #173. This doc is the durable record; the issue will
close. Supersedes the premise of #170 (closed as wrong-fix). Related: #174
(label-cardinality hardening, separate).

## One-line summary

smtpd runs a privileged parent that serves `/metrics` plus one short-lived
`protocol-handler` subprocess per connection that does the actual recording. The
process that records a metric is gone before Prometheus scrapes, so the parent
has to collect each child's counts back over IPC. This doc explains why the
obvious fix does not work here and how the aggregation is built.

## Why the imapd/pop3d fix does not apply

imapd and pop3d are single long-lived processes: the same process records
metrics and serves `/metrics`, so wiring a `PrometheusCollector` onto
`prometheus.DefaultRegisterer` is enough (see `cmd/imapd/main.go`,
`cmd/pop3d/serve.go`).

smtpd is different by design. `internal/smtpd/smtp/subprocess.go`'s
`SubprocessServer` accepts a connection, forks+execs `smtpd protocol-handler`,
passes it the raw TCP socket as fd 3, and the child (`cmd/smtpd/handler.go`)
handles exactly one SMTP session and exits. The subprocess model exists for
fault isolation (one crash cannot take the daemon down) and for the optional
`HandlerUID` credential drop (see `docs/` in infodancer/infodancer,
`mail-security-model.md`).

Constructing a `PrometheusCollector` inside the child -- the naive fix proposed
in #170 -- registers it to a registry that lives only in that child. The child
never runs an HTTP server and exits before anything scrapes it, so `/metrics`
(served by the parent) still shows zero `smtpd_*` series. That is why #170 was
closed and re-scoped as #173.

## Ownership split: parent-owned vs. child-reported

Not every series travels over IPC. Two are owned by the parent directly because
it already has the exact lifecycle signal and deriving them from ephemeral
children is either wrong or fragile:

- **`smtpd_connections_active`** (gauge): parent `Inc` on `cmd.Start`, `Dec` in
  the reaper after `cmd.Wait`. Stays correct even when a child crashes -- the
  reaper still runs. A child cannot report a live gauge meaningfully: its
  open/close nets to zero, or leaks on crash.
- **`smtpd_connections_total`** (counter): parent counts spawns, which also
  counts connections whose child died before it could report anything.

Everything else is an **additive per-session delta** reported by the child at
exit: `messages_received_total` + `messages_size_bytes`,
`messages_rejected_total`, `tls_connections_total`, `auth_attempts_total`,
`commands_total`, `deliveries_total`, `spf/dkim/dmarc_checks_total`,
`rbl_hits_total`, `rspamd_checks_total` + `rspamd_scores`. All counters and
histograms, all commutative under summation -- which is what makes aggregation
safe regardless of how children interleave or in what order reports arrive.

The child reuses the full `NewPrometheusCollector`, so it *does* record the
connection families too; the parent aggregator drops them by name (see
`parentOwnedFamilies` in `internal/smtpd/metrics/aggregate.go`).

## The IPC channel: an inherited anonymous pipe

`spawnHandler` already hands the child the TCP socket as `cmd.ExtraFiles[0]`
(fd 3). When metrics are enabled it also creates a `pipe(2)` and passes the
**write end** as `cmd.ExtraFiles[1]` (fd 4), keeping the read end. The child
writes its report to fd 4 just before exiting; the parent's reaper reads the
read end to EOF, decodes, and folds the result into the aggregate.

Why a pipe rather than a filesystem unix socket:

- **No new addressable object.** An anonymous pipe fd is reachable only by the
  child that inherited it and drains only to this parent. There is no path on
  disk for another local uid to connect to, and no listener to fuzz.
- **Direction is structural.** The child holds only the write end; the parent
  holds only the read end. The channel physically cannot carry data parent ->
  child, so it can never influence a (possibly lower-privileged, under
  `HandlerUID`) handler. One-way by construction, not by convention.
- **Survives the credential drop.** An already-open inherited fd needs no
  filesystem permission to write, so it works in both the drop and no-drop
  (dev/rootless) paths.
- **Does not block teardown.** The report is small (pre-aggregated counters plus
  two tiny histograms), well under the 64 KiB Linux pipe buffer, so the child
  writes it in one non-blocking `write` and exits without waiting on the parent.

The parent drains the pipe *before* `cmd.Wait`, having already closed its own
copy of the write end, so the read returns EOF exactly when the child exits and
closes fd 4. Ordering is deadlock-free because the report always fits the pipe
buffer.

Config keeps both ends consistent: the parent creates fd 4 only when
`cfg.Metrics.Enabled`, and the child (which re-reads the same config) writes to
fd 4 only when enabled. If `os.Pipe` fails the parent runs the child without
fd 4 and the child's flush degrades to a logged debug -- never fatal, never a
dropped connection.

## Wire format and aggregation (Option B)

The child records into `NewPrometheusCollector` on a **private**
`prometheus.NewRegistry()` rather than the global default (see
`NewHandlerCollector` in `internal/smtpd/metrics/report.go`). This keeps metric
names, labels, and histogram buckets defined in exactly one place, shared by the
child recorder and -- via aggregation -- the parent's exposed endpoint.

At exit the child calls `WriteReport`, which `Gather()`s the private registry and
writes the families as **length-delimited protobuf** using
`expfmt.NewFormat(expfmt.TypeProtoDelim)` -- the standard Prometheus exposition
format, so there is no bespoke framing to version. The read is bounded to 64 KiB
(`maxReportBytes`) so a misbehaving or compromised lower-privileged child cannot
drive unbounded allocation in the privileged parent.

The parent's `aggregator` (`internal/smtpd/metrics/aggregate.go`) is an unchecked
`prometheus.Collector` (its `Describe` sends nothing, because families and label
combinations are discovered at runtime). `ingest` decodes a report and folds it
under a mutex:

- **Counters** accumulate by value, keyed by their sorted label set.
- **Histograms** accumulate sample count, sample sum, and per-upper-bound
  cumulative bucket counts. Because all children share identical bucket layouts,
  summing cumulative bucket counts is exact and reproduces what an in-process
  collector would have observed.

`Collect` re-emits the running totals with `MustNewConstMetric` /
`MustNewConstHistogram`. `ParentMetrics` wraps the aggregator plus the two
parent-owned connection metrics and a new `smtpd_handler_failures_total{reason}`
counter.

Two encodings were considered. This one (Option B: ship `Gather()` output as the
standard protobuf exposition format, aggregate in the parent) was chosen over
Option A (a bespoke delta message applied via standard atomic metrics) because it
keeps metric definitions DRY and uses a stable wire schema; the cost is the
aggregating collector and the connection-family skip list. See #173 for the full
comparison.

## Failure handling

- **Child crashes before/while writing:** the length-delimited decoder returns
  an error on a truncated frame; the parent drops the report, logs at debug, and
  increments `smtpd_handler_failures_total{reason="metrics_decode"}`. Lost
  metrics for one aborted session are a rounding error, and the failure itself
  becomes observable -- which it was not before.
- **Malformed or oversized report:** bounded read plus strict decode; Go's proto
  decoder is memory-safe, and the size cap covers the allocation angle. Dropped
  and counted, never trusted.
- **`connections_active` on crash:** unaffected -- the parent owns it and the
  reaper's `Dec` runs regardless of how the child died.

## Concurrency

Many reaper goroutines call `ParentMetrics.Ingest` concurrently; the aggregator
guards its family map with one mutex, and `Collect` takes it as well. The
parent-owned connection and failure metrics are standard Prometheus types whose
`Inc`/`Dec`/`Add` are atomic.

## Security notes

The channel is one-way child -> parent, anonymous, inheritance-only; it gives a
child no new reach into the parent beyond delivering bytes the parent already
treats as untrusted (bounded read, strict decode, drop-and-count). The parent is
the hardened side because it parses lower-privileged input.

Not addressed here, tracked as #174: a hostile sender can spray distinct
`sender_domain` values (SPF/DKIM/DMARC/rspamd labels are set pre-auth from the
wire) and inflate label cardinality in the parent's registry. This risk predates
this design -- it also exists in the imapd/pop3d in-process collectors -- but the
aggregating parent is where it bites hardest. The bound (allowlist known domains,
bucket the rest into `other`) belongs in the collector layer so it applies to
both the in-process and aggregated paths.

## Code map

| Concern | Location |
|---------|----------|
| Child collector on private registry; report writer | `internal/smtpd/metrics/report.go` |
| Parent aggregating collector; `ParentMetrics`; parent-owned + failure metrics | `internal/smtpd/metrics/aggregate.go` |
| Pipe (fd 4) creation, connection accounting, report drain in the reaper | `internal/smtpd/smtp/subprocess.go` |
| Parent constructs `ParentMetrics`, serves `/metrics` | `cmd/smtpd/serve.go` |
| Child records over fd 4, flushes report at session end | `cmd/smtpd/handler.go` |
| Series definitions (shared by child and, transitively, parent) | `internal/smtpd/metrics/prometheus.go` |
| Tests: round-trip, summation, skip, garbage, accounting, pipe EOF | `internal/smtpd/metrics/aggregate_test.go` |

## Not done

No subprocess-spawning integration test: exercising the real fd-4 handoff through
a forked child needs a running session-manager, matching the existing stub in
`internal/smtpd/smtp/integration_test.go`. The unit tests cover every seam of the
aggregation logic and the real `os.Pipe` EOF-drain path; the actual fork/exec
handoff is not yet covered end to end.
