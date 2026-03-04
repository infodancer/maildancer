# CLAUDE.md — queue-manager

Mail queue driver for the infodancer mail stack.

## Role in the Stack

`queue-manager` owns the retry loop. It scans the on-disk queue, applies
exponential backoff based on envelope file mtime, and invokes `mail-remote`
for delivery. It also sweeps expired entries (TTL cleanup).

See `infodancer/infodancer/docs/queue-design.md` for the full queue structure.

## Queue Layout

```
queue/
  msg/{tld}/{domain}/{msgid}                   # message bodies (by sender domain)
  env/{tld}/{domain}/{localpart}@{msgid}.{n}   # envelopes (by recipient domain)
```

`queue-manager` reads from `env/` to drive delivery; reads `msg/` only to
locate the body file path for `mail-remote`. It never reads message content.

## CLI

```
queue-manager [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--queue path` | (required) | Root of the mail queue directory. |
| `--binary path` | `mail-remote` | Path to the mail-remote binary. |
| `--smarthost h:port` | | Pass `--smarthost` to every mail-remote invocation. |
| `--smarthost-user u` | | Pass `--smarthost-user` to every mail-remote invocation. |
| `--interval dur` | `1m` | Queue scan interval. |
| `--once` | false | Scan once and exit (cron / testing). |

## Backoff Model

Envelope mtime = time of last delivery attempt (updated by mail-remote).
The minimum retry interval is 5 minutes. No retry state is stored in the file.
The queue-manager scan interval provides the upper bound on retry frequency.

## TTL and Cleanup

- Body files and envelope files stay on disk until their TTL expires.
- No ref counting. No early body deletion on success.
- On TTL expiry: one final SMTP delivery attempt, then envelope deleted.
- Expired body files are swept separately.

## Development Commands

```bash
task build    # build the binary
task test     # run tests with race detector
task lint     # run golangci-lint
task check    # build + test + vet + lint + vulncheck
```
