# Go Development Conventions

Conventions for the maildancer monorepo. They favor simplicity, modularity, and
readability, and follow the [Google Go Style Guide](https://google.github.io/styleguide/go/decisions)
and [Effective Go](https://go.dev/doc/effective_go).

---

## 1. Project structure

maildancer is a single Go module. Code is organized by component:

```plaintext
/msgstore            Shared storage library + interfaces (top-level, importable)
/auth                Authentication & key management (top-level, importable)
/cmd/<binary>        Main entrypoints — minimal logic, wire up and call internal/
/internal/<module>   Per-daemon implementation (not importable outside the module)
/internal/authoidc   OIDC server behind cmd/auth-oidc
```

- Place only the entrypoint in `cmd/<binary>/main.go`; keep implementation in
  the module's package.
- `msgstore` and `auth` are top-level because they are shared, reusable
  libraries. Everything daemon-specific lives under `internal/`.
- Each module keeps its own `errors/` package for centralized error definitions.

---

## 2. Architectural boundaries

Privilege separation is enforced by depguard rules in `.golangci.yml`. The
protocol daemons (`smtpd`, `pop3d`, `imapd`) must not import `msgstore`, `auth`,
or `auth/*` directly — authentication, domain routing, and delivery go through
`session-manager` over gRPC. Do not relax these rules to take a shortcut; route
through session-manager instead.

---

## 3. Modularity & simplicity

- **Single responsibility:** every file, type, and function does one thing.
- **Short functions:** keep functions focused; prefer extraction over long bodies.
- **Descriptive names:** meaningful file, type, and function names. No
  abbreviations except common ones (`ctx`, `err`, `req`, `resp`, `cfg`).

---

## 4. Error management

- **Centralize per module:** define error types and helpers in the module's
  `errors/` package.
- **Propagate, don't swallow:** return errors to a single handling point.
- **Wrap with context:** `fmt.Errorf("context: %w", err)`.
- **No silent failures:** always check and return errors. `errcheck` enforces
  this repo-wide; the only allowed unchecked calls are stream `Close()` and
  `fmt.Fprint*` (see `.golangci.yml`).

---

## 5. Logging

- Structured logging via `slog` throughout.
- Network daemons expose Prometheus metrics with domain-level aggregation only —
  no per-user metrics (privacy).

---

## 6. Code quality

- **DRY:** factor repeated logic into helpers.
- **Readability over cleverness:** comment non-obvious logic.
- All code must pass `task all` (build, lint, vulncheck, test) before push; the
  pre-push hook runs it.

---

## 7. Security

This is a security-sensitive codebase. Follow secure-by-design practices:
validate all input, use the established crypto (NaCl box; Argon2id for password
hashing), never log secrets, and acquire privilege at the last possible moment
(uid/gid set by the parent via `SysProcAttr.Credential`, never self-setuid).

---

## References

- [Google Go Style Guide](https://google.github.io/styleguide/go/decisions)
- [Effective Go](https://go.dev/doc/effective_go)
