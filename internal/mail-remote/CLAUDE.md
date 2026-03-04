# CLAUDE.md — mail-remote

Remote delivery agent for the infodancer mail stack.

## Role in the Stack

`mail-remote` is invoked by `queue-manager` (or by hand) to deliver outbound
mail. It reads a message body file and one or more envelope files, then delivers
via SMTP or the new messaging protocol based on DNS discovery.

See `infodancer/infodancer/docs/queue-design.md` for the full queue structure.

## CLI

```
mail-remote [flags] <body-file> <envelope-file> [envelope-file ...]
```

- Body file is always the first argument.
- One or more envelope files follow.
- All envelope files must share the same recipient domain (the queue-manager
  enforces this grouping by domain directory).

## Flags

| Flag | Description |
|------|-------------|
| `--smarthost host:port` | Relay via SMTP smarthost (STARTTLS). |
| `--smarthost-user user` | SMTP AUTH username. Password from `MAIL_REMOTE_PASSWORD` env var. |

DNS-based delivery (SRV → new-protocol; MX → SMTP; A → SMTP) is not yet
implemented. `--smarthost` is required until it is.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All envelopes delivered. Envelope files deleted. |
| 1 | Fatal error (bad arguments, unreadable files). |
| 69 | Permanent failure (EX_UNAVAILABLE). Caller deletes envelopes. |
| 75 | Temporary failure (EX_TEMPFAIL). Caller retries. Envelope mtime is updated. |

## Envelope File Format

Plain text, one field per line:

```
TTL 2026-03-07T10:00:00Z
SENDER bounces+alice=gmail.com@origin.example.com
RECIPIENT alice@gmail.com
MSGID abc123def456789
```

`SENDER` is the VERP-encoded MAIL FROM address, computed at queue-inject time.
`TTL` is an absolute RFC3339 timestamp.

## Development Commands

```bash
task build    # build the binary
task test     # run tests with race detector
task lint     # run golangci-lint
task check    # build + test + vet + lint + vulncheck
```

## Key Packages

| Package | Purpose |
|---------|---------|
| `internal/envelope` | Parse and validate envelope files |
| `internal/smtp` | SMTP delivery (smarthost; direct TBD) |
