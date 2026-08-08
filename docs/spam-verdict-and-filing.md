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
the outbound `EnqueueMetadata`. The reason is not "outbound has no Junk folder"
-- there is a real case for scanning outbound mail (an ISP policing its own
customers to protect shared sending-IP reputation). The reason is that outbound
policing acts **synchronously at submission**, where the authenticated identity
is known -- reject/quarantine/rate-limit/alert -- not by deferring a verdict
downstream into the queue, by which point we have already accepted
responsibility for relaying the message. Carrying the verdict on the outbound
channel would therefore act at the wrong point.

That makes outbound abuse control a separate feature (direction-aware rspamd
rules so we do not bounce legitimate customer mail, plus per-account rate/abuse
tracking), tracked as [#144]. The one outbound-carry that could earn its place
there *later* is the score as forensic metadata on a quarantined message -- not
for filing. Relaying/forwarding still carries the `X-Spam-*` headers in the
message body as before.

## Reaching the verdict from Sieve (issue [#244])

Carrying the verdict out of band keeps it unforgeable, but it also puts it out
of reach of a Sieve script, which sees only the message and envelope. Without a
channel to it, users could tighten policy only by testing the advisory
`X-Spam-*` headers -- the in-band labels this design declines to trust.

Sieve's **environment** extension (RFC 5183) is that channel: items come from
the runtime, not the message, so they carry the same provenance guarantee as the
verdict. mail-session supplies an `interp.Env` in `runSieve`:

| Item | Value |
|---|---|
| `vnd.maildancer.spam-value` | RFC 5235 0..10 integer, from the verdict's `X-Spam-Value` |
| `vnd.maildancer.spam-flag` | `YES`/`NO` from `IsSpam` |
| `vnd.maildancer.spam-score` | the raw score, two decimals |
| `name`, `location`, `phase`, `host`, `version` | RFC 5183 section 4.1, as far as they can be answered |

```sieve
require ["fileinto", "environment", "relational", "comparator-i;ascii-numeric"];
if environment :value "ge" :comparator "i;ascii-numeric" "vnd.maildancer.spam-value" "5" {
    fileinto "Junk";
}
```

Threshold rules must use `spam-value`, not `spam-score`: `i;ascii-numeric`
(RFC 4790) is defined over non-negative integers, so it reads `12.80` as `12`
and a negative ham score has no defined ordering.

**nil vs clean survives into Sieve.** When no scan ran, the spam items report
*unsupported* rather than empty, and RFC 5183 section 4 makes a test against an
unsupported item fail unconditionally. So a threshold rule does not fire on
unscanned mail instead of comparing against an invented zero. The direction that
matters is the clean side: a rule keying on a *low* value would otherwise sort
unexamined mail as though a scanner had vouched for it.

Items mail-session cannot answer -- `remote-host`, `remote-ip`, `domain` --
report unsupported too. It runs privilege-dropped after the SMTP conversation
has ended and never saw the client.

## The system default script

Filing has to work for users who have written no Sieve at all -- there is still
no editor, so most never will. mail-session therefore falls back to a site-wide
script when the recipient has none.

**Location: the root of the mail data tree, `system.sieve`, mode 0644.** Not the
config tree: by the time a script is read, mail-session has dropped to the
recipient's uid and cannot reach the config tree at all (the same constraint
that makes a domain `forwards` file unreadable there). The data root is
traversable by every recipient and the script holds no secrets. The shipped copy
lives at `/usr/share/maildancer/system.sieve` in the all-in-one image; installing
it is a deliberate `cp`, so filing policy is never switched on by an upgrade.

**User script replaces it; the two are never chained.** Partly because RFC 5228
implicit keep and `fileinto` do not compose across independent scripts without
inventing semantics the RFC does not define -- but mainly because a user who
writes rules owns their policy. Re-applying the site default on top would
quietly overrule a deliberate choice to leave flagged mail in the inbox.

"Exists but is unusable" is distinct from "does not exist": a user whose script
is unreadable or over the size cap gets *no* filtering, not the site default in
its place. Falling back there would hand their policy back to the server without
anything saying so.

**The default keys on `spam-flag`, not a threshold.** rspamd already refuses what
it is confident about at SMTP time; the default covers the band below that, and
inventing a second number here would be a worse copy of a decision rspamd makes
with far more context. The script documents the `spam-value` threshold form for
operators who want to be stricter.

A broken system script falls through to implicit keep, like any other script --
which matters more here, because it fails for every account at once rather than
one.

### It does not train Bayes, and must not start

Training fires on IMAP `MOVE`/`COPY` across the Junk boundary (`triggerLearn` in
imapd's `storeops.go`). Delivery-time filing performs no IMAP operation, so it
trains nothing -- correct by construction, and worth keeping that way.

The distinction is what makes the corpus useful. Auto-filed mail is the
classifier's *own* guess; training on it would reinforce whatever it already
believes. The signal worth learning from is the user disagreeing: moving a
message out of Junk (ham -- a false positive) or into it (spam -- a false
negative). Enabling this default should, over time, start populating the ham
side, which is otherwise starved because nothing lands in Junk to be dragged
back out.

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
- Outbound abuse control (direction-aware scanning + per-account rate/abuse
  tracking to protect sending-IP reputation) is a separate feature, [#144]. It
  is not a rider on inbound verdict carriage; see "Outbound is excluded" above.
- A per-user Sieve editor remains a separate, broader gap; this work does not
  depend on it.

[#133]: https://github.com/infodancer/maildancer/issues/133
[#143]: https://github.com/infodancer/maildancer/issues/143
[#144]: https://github.com/infodancer/maildancer/issues/144
