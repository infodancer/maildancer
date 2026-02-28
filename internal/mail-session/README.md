# mail-session

Privilege-separated mail retrieval agent for the infodancer mail stack.

`mail-session` is spawned by the pop3d or imapd dispatcher after successful authentication. It runs as the authenticated user's uid and domain gid, performs all maildir operations (list, fetch, delete, flag), and communicates with the protocol handler over pipes using a simple line-based session protocol.

Part of the [infodancer mail stack](https://github.com/infodancer/infodancer). See the [security model](https://github.com/infodancer/infodancer/blob/master/docs/mail-security-model.md) for the full process separation architecture.

## Security Model

- Never runs as root
- Spawned with `uid=user, gid=domain` by the dispatcher after auth
- Reads from stdin, writes to stdout (pipes managed by dispatcher)
- Has no network access — filesystem only
- Exits when the session ends or the pipe closes

## Development

```bash
task build      # Build the binary
task test       # Tests with race detector
task check      # All CI checks (test, vet, fmt, lint, vulncheck)
task hooks:install  # Install git hooks
```

## License

MIT
