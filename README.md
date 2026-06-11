# maildancer

Mail server suite and local filesystem auth for infodancer.
Monorepo of the former smtpd, pop3d, imapd, session-manager, mail-*, queue-manager, msgstore, auth, and webadmin repositories.

## Quick Start

Bring up the full stack from the repo root:

```bash
docker compose up -d
```

This starts smtpd (25/587), pop3d (110), imapd (143), session-manager, queue-manager,
webadmin (http://localhost:8080), auth-oidc (http://localhost:9000), and Redis.

A fresh stack has no domains or users -- mail flow won't work until you provision at
least one. Use webadmin at http://localhost:8080 or the `userctl` CLI
(`cmd/userctl`) to add a domain and users.

See [deploy/README.md](deploy/README.md) for the full topology, provisioning steps,
TLS/outbound relay setup, and teardown instructions.
