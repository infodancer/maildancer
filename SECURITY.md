# Security Policy

maildancer is a mail server and authentication suite. Security issues here can
expose mail content, credentials, or allow unauthenticated access, so they are
taken seriously and handled privately until a fix is available.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

Use [GitHub's private vulnerability reporting](https://github.com/infodancer/maildancer/security/advisories/new)
to submit your report. This keeps the details private while the issue is
assessed and fixed.

Please include, as far as you can:

- the component affected (smtpd, pop3d, imapd, session-manager, mail-deliver,
  mail-session, mail-remote, queue-manager, auth, msgstore, webadmin, auth-oidc);
- the version, commit, or release tag you tested;
- a description of the impact and, if possible, a minimal reproduction.

You should expect an initial response within 72 hours. We will work with you to
understand the issue and coordinate a fix and a disclosure timeline.

## Scope

This policy covers the code in this repository on the `main` branch and the
most recent tagged release. The project is pre-1.0; there is no long-term
support branch yet.

The following are generally **out of scope**:

- vulnerabilities in third-party dependencies (report those upstream; we will
  pick up the fix on update);
- issues that require a misconfiguration explicitly warned against in the docs
  (for example, running plaintext submission/retrieval over an untrusted
  network);
- denial of service from unrealistic traffic volumes against a single host.

## Security model

maildancer is built around qmail-inspired privilege separation: no
network-facing process holds filesystem access to mail data, and no single
process holds credentials for more than one user at a time. The authoritative
design documents (threat model, encryption design, privilege model) live in the
[`infodancer/infodancer`](https://github.com/infodancer/infodancer) repository
under `docs/`. Read those before reasoning about a finding's impact.
