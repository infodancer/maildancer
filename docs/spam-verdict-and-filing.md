# Spam verdict carriage and default spam filing

Status: design (issue [#133]). This document supersedes an earlier draft that
proposed a header-driven system Sieve rule; see "Why not the header" below for
what changed and why.

Scope of the current phase: **carry** the upstream spam verdict end-to-end on
the delivery channel. What the delivery side *does* with it (file to Junk, etc.)
is deliberately a later phase.

## Problem

rspamd runs once, at SMTP time in smtpd. When it returns `add header` -- spam
below the reject threshold -- the message is accepted and delivered to the
inbox. There is no server-side mechanism that files flagged mail into Junk, and
no per-user Sieve editor exists, so users cannot author the rule themselves.
Correctly-flagged spam lands in the inbox.

## Why not the header (the pivot)

The obvious approach -- the one Dovecot's `sieve_before` uses -- is to have the
delivery agent key on the message's `X-Spam-Flag: YES` header. We rejected it
on a trust argument:

- **The header is in-band, and in-band means forgeable.** `X-Spam-*` is *our*
  namespace, but the header rides in on data the sender controls. A sender can
  pre-set `X-Spam-Flag: YES` on a *ham* message; rspamd scores it clean and we
  stamp `X-Spam-Flag: NO` on top, but the sender's forged `YES` remains below.
  A Sieve `header :contains "X-Spam-Flag" "YES"` test matches *any* field with
  that name -- including the forgery -- so the victim's legitimate mail is filed
  to their Junk. Low severity (recoverable, and it's the sender's own mail), but
  it is exactly the trusted-header-spoofing class we should not build on.
- **The usual fix -- strip inbound `X-Spam-*` at ingress -- means mutating the
  message.** Stripping this specific namespace is in fact DKIM-safe (no
  legitimate signer lists `X-Spam-*` in `h=`, and DKIM only protects listed
  headers), but message surgery is a smell: it interacts badly with ARC,
  S/MIME, and PGP protected-headers, and "don't rewrite mail you're storing" is
  a sound default. The forgeability is the real problem; stripping only papers
  over it.

## Chosen approach: carry the verdict out of band

Do not trust an in-band, self-asserted label. Carry the scanner's verdict on a
channel whose provenance we control: the delivery gRPC path
(smtpd -> session-manager -> mail-session). smtpd already holds the verdict
(`spamcheck.CheckResult`) at delivery time; it attaches it to the delivery
metadata, and it travels alongside the message to the delivery agent. A sender
cannot forge it because it never appears in the message -- it originates in our
scanner and travels our wire.

The verdict carried is the **full** result: `is_spam` (bool), `score` (double),
and the complete `X-Spam-*` header set (name -> value). Carrying the whole thing
(not just a bool) lets the delivery side apply whatever policy we later choose --
a score threshold, per-domain rules, header inspection -- without another round
trip or another proto change.

smtpd still stamps the `X-Spam-*` headers onto the message itself (the earlier
commit in this branch). That stays, but its role is now clearly scoped: the
on-message headers are **advisory**, for the recipient's own client-side filters
and for human inspection. The **authoritative** signal for server-side policy is
the out-of-band verdict. Two copies, two consumers, no conflict.

## What this phase builds (carriage only)

The wire and struct plumbing to move the verdict end-to-end. No delivery-side
behavior: the verdict lands in `deliver.DeliverRequest` and is not yet read.

1. **Proto** (`internal/mail-session/proto/mailsession/v1/delivery.proto`): a new
   `SpamVerdict` message (`is_spam`, `score`, `map<string,string> headers`) and
   `DeliverMetadata.spam_verdict = 9`. Regenerated with the recorded `protoc`
   invocation.
2. **smtpd** (`internal/smtpd/smtp/smdeliver.go`, `session.go`): `Deliver` takes
   a `*spamcheck.CheckResult`; `spamVerdictProto` converts it (nil when no scan
   ran). Threaded through `followRedirect` so the local forward-target delivery
   carries it too.
3. **session-manager** (`grpcserver/delivery_proxy.go`): forwards the metadata
   chunk verbatim, so the verdict passes through unchanged -- no change needed.
4. **mail-session** (`grpcserver/delivery.go`): `deliverRequestFromMetadata`
   maps the wire verdict into `deliver.DeliverRequest.Spam` (a `*SpamVerdict`,
   nil when absent).

### nil vs. clean

`Spam == nil` means **no scan ran** (spamcheck disabled or absent). A non-nil
verdict with `IsSpam == false` means **scanned and judged clean**. Delivery-side
policy must honor that distinction -- "no verdict" is not "not spam".

### Outbound is excluded

The verdict rides only on the local-delivery channel (`DeliverMetadata`), not on
the outbound `EnqueueMetadata`. Its purpose is local Junk filing, and outbound
mail has no Junk folder to file into, so carrying it there would dead-end.
Relaying/forwarding still carries the `X-Spam-*` headers in the message body as
before.

## Best practices retained (for the delivery-side phase)

- **The MTA marks; the MDA files.** rspamd/smtpd only decide a verdict; the
  delivery pipeline files. Unchanged.
- **Reject the worst at SMTP; file only the borderline.** rspamd's `reject`
  action still refuses high-confidence spam at SMTP. The verdict covers the
  lower `add header` band. `reject_threshold = 0` (defer to rspamd's action) is
  the intended shape.
- **Act on the verdict, never re-scan.** No rspamd stage in the delivery
  pipeline; that stays.
- **File to Junk, never discard.** False positives must be recoverable.
- **Do not double-train Bayes.** Server-side filing performs no IMAP `MOVE`, so
  it triggers no learn -- correct by construction; keep it that way. Only
  user-initiated moves train (spam on move-in, ham on move-out of Junk).

## Related

- The IMAP IDLE new-mail notification folder is currently a guess derived from
  the rspamd action, not the actual delivery destination ([#143]). When the
  delivery side starts filing to Junk, that guess should be replaced by the real
  destination reported back in `DeliverResponse`.
- A per-user Sieve editor remains a separate, broader gap; this work does not
  depend on it.

[#133]: https://github.com/infodancer/maildancer/issues/133
[#143]: https://github.com/infodancer/maildancer/issues/143
