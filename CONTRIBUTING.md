# Contributing to maildancer

Thanks for your interest. maildancer is a mail server and authentication suite,
so correctness and security matter more than speed -- expect review to focus on
those. This document covers the workflow; [CONVENTIONS.md](CONVENTIONS.md) covers
the Go coding standards.

## Before you start

- **File an issue first.** Every change starts from a GitHub issue describing the
  bug or the feature. This keeps design discussion out of the diff.
- **Security vulnerabilities do not go in public issues.** Use the private
  reporting path in [SECURITY.md](SECURITY.md).

## Workflow

1. Branch from `main`, named after the issue:
   - `feature/<issue-number>` for features
   - `bug/<issue-number>` for fixes
2. Make small, logical, self-contained commits. Don't bundle unrelated changes
   in one commit. Reference the issue in each commit (`Refs #NN`, or `Closes #NN`
   on the commit that completes it).
3. Run the full check suite before pushing:
   ```bash
   task all      # build + lint + vulncheck + test
   ```
   Installing the git hooks (`task hooks:install`) runs the relevant checks
   automatically on commit and push.
4. Open a pull request against `main`. Describe what changed and why, and link
   the issue. Keep the PR scoped to one concern -- several small PRs review
   faster than one large one.

## Requirements

- **Go 1.26 or newer** (`go.mod` pins the toolchain).
- [Task](https://taskfile.dev/) for the build/test targets.
- Tests are expected for behavioral changes. This project leans on
  test-driven development; a fix without a regression test will usually be sent
  back for one.

## Architectural boundaries

A few boundaries are enforced by lint rules, not just convention, because
violating them reintroduces bugs the design deliberately avoids:

- The network daemons (`smtpd`, `pop3d`, `imapd`) **must not** import `msgstore`,
  `auth`, or `auth/*` directly. Authentication, domain routing, and delivery go
  through `session-manager` over gRPC. `depguard` in `.golangci.yml` fails the
  build on violations -- route through session-manager rather than relaxing the
  rule.
- Address normalization happens in exactly one place (`auth/domain.AuthRouter`).
  Daemons pass addresses straight through to `msgstore`.
- OS uid/gid are identity allocation, not configuration, and are written through
  one shared code path (`userctl` / `webadmin`). Don't add a uid or gid to any
  merged config file.

If a change seems to need crossing one of these boundaries, that's a design
discussion for the issue, not something to work around in the PR.
