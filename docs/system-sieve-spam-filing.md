# System Sieve and default spam-to-Junk filing

Status: design (issue [#133])
Scope: `internal/smtpd` (header stamping), `internal/mail-session/deliver`
(system sieve layer), `msgstore` (unchanged -- `fileinto` already works)

## Problem

rspamd runs once, at SMTP time in smtpd. When it returns `add header` -- spam
below the reject threshold -- the message is accepted and delivered to the
inbox. There is no server-side mechanism that files flagged mail into Junk, and
no per-user sieve editor exists, so users cannot author the rule themselves.
Correctly-flagged spam lands in the inbox.

We want a **system-level default**: mail rspamd flags as spam is filed to Junk
with no per-user configuration, config-gated, without a second rspamd scan and
without interfering with Bayes training on manual moves.

## Chosen approach: a system Sieve script (issue #133 option B)

File flagged mail with a built-in `sieve_before`-style system script that runs
ahead of (and independently of) any per-user script:

```sieve
require ["fileinto"];
if header :contains "X-Spam-Flag" "YES" {
    fileinto "Junk";
    stop;
}
```

This is the same mechanism Dovecot's `sieve_before` and the rspamd integration
guides use. The verdict travels to the delivery agent as a message header, the
policy lives in Sieve (standard, auditable, composable), and the `fileinto`
write path already exists and auto-creates the target folder. The system-script
layer is reusable for future default rules (list filing, vacation defaults),
not just spam.

Rejected alternatives (from #133): a hardcoded Go rule in the delivery agent
(option A) bakes policy into Go and forces us to re-implement Sieve's action
ordering when a user script also runs; the hybrid (option C) is two code paths
with divergence risk. Neither is justified given the Sieve engine is already in
the pipeline with working `fileinto`.

## The split, and why it is already almost right

Best practice for spam handling is a clean division of labor:

- **The MTA marks; the MDA files.** rspamd/smtpd only decides a verdict and adds
  headers. It never moves mail between folders. The filing decision belongs to
  the delivery pipeline in mail-session. maildancer already respects this.
- **Reject the worst at SMTP; file only the borderline.** rspamd's `reject`
  action still refuses high-confidence spam at SMTP ("reject early, never
  bounce"), where the sender sees the rejection and nothing is silently lost.
  The Junk rule keys off the lower `add header` band. Reject and Junk-filing are
  complementary, non-overlapping tiers -- `reject_threshold = 0` (defer to
  rspamd's action) plus a Junk rule is the intended shape, not a bug.
- **Act on the header, never re-scan.** The delivery pipeline files off the
  header smtpd already stamped. It does not call rspamd again. The pipeline has
  no rspamd stage today; it stays that way.
- **File to Junk, never discard.** False positives must be recoverable. Confident
  spam is refused at SMTP; borderline spam is filed, never dropped.

## Prerequisite: smtpd must stamp the spam headers (this is a real gap)

**The X-Spam-* headers are computed and then thrown away.** smtpd's rspamd
client builds `X-Spam-Flag`, `X-Spam-Status`, `X-Spam-Score`, `X-Spam-Checker`
into `checkResult.Headers`, but `session.go` only ever prepends the RFC 5321
`Received` trace header (`withHeaders(received, tmp)` at every Enqueue/Deliver
call). `checkResult.Headers` is never written onto the delivered bytes. No
message carries `X-Spam-Flag` today. The header-driven Sieve rule therefore
cannot work until this is fixed -- and stamping computed spam headers is
correct on its own merits (client-side filters and user inspection rely on
them).

A related inconsistency in the same block: when `checkResult.Action ==
ActionFlag`, smtpd sends the IMAP IDLE new-mail notification for folder `"Junk"`
(`session.go` ~line 710) while actually delivering to INBOX -- the notification
already lies about the destination. Once the Sieve rule files flagged mail to
Junk for real, that notification becomes truthful, provided both the header
stamp and the notification are driven by the **same** predicate.

### Stamping design

- Gate on `SpamCheck.AddHeaders` (already in config). When enabled and a check
  result exists, prepend `checkResult.Headers` to the message bytes ahead of the
  `Received` header, at every delivery/enqueue site in `session.go`
  (local deliver, remote enqueue, forward paths).
- The header block must be built once and reused so local delivery, remote
  enqueue, and forwarding all carry identical headers.
- Order: spam headers, then `Received`, then original message. (RFC 5321 wants
  the freshest `Received` on top of the *received* message; the locally-added
  X-Spam-* headers sit above it as this hop's annotations. Header order among
  our own added fields is not semantically significant.)
- Stamp `X-Spam-Flag: YES` exactly when the notification predicate fires
  (`checkResult.Action == ActionFlag`), so filing and notification cannot
  disagree.

This prerequisite is a **separate, self-contained commit** landed before the
Sieve work.

## System Sieve layer in mail-session

### Composition semantics

`foxcpp/go-sieve` executes one script per `Load`/`Execute`, each with its own
`RuntimeData` and `AppliedActions`. We run the system script first, digest its
outcome (existing `digestActions`), and decide:

- **System script claimed the message** (produced a `fileinto`/`redirect`/
  `reject`, or otherwise cancelled implicit keep -- i.e. it hit `stop` after an
  action): apply the system outcome and do **not** run the user script. This is
  the spam path: `fileinto "Junk"; stop;`.
- **System script did nothing** (implicit keep still stands -- not spam): fall
  through to the per-user script exactly as today. If there is no user script,
  fall through to normal delivery (implicit keep to INBOX).

"Claimed" is read from the system run's implicit-keep state: if implicit keep
was cancelled, the system layer took a terminal action and owns the outcome.
This is a deliberately simpler model than Dovecot's shared-context action
accumulation -- "system rules get first refusal; if they take no delivery
action, user rules run." It is exactly right for the spam use case and easy to
reason about. Full sieve_before/after accumulation can come later if a real
need appears; document the limitation rather than half-implement it.

### Where the system script comes from

- A built-in default spam rule, embedded in the binary (`//go:embed` or a Go
  string constant), so the feature is zero-config and always available.
- Config-gated by a new delivery flag (below). Default **off** until the header
  stamping is deployed and verified in prod, then flip on; document both states.
- Optional future: a config path for an operator-supplied system script that
  overrides/extends the embedded default (global first; per-domain later). Not
  required for the first cut -- note it, do not build it.

### Config

Add to `deliver.Config` (`internal/mail-session/deliver/config.go`):

```go
// FileSpamToJunk enables the built-in system Sieve rule that files
// messages flagged X-Spam-Flag: YES into the Junk folder before any
// per-user script runs. Requires smtpd to be stamping spam headers
// (SpamCheck.AddHeaders). Default false.
FileSpamToJunk bool `toml:"file_spam_to_junk"`
```

`session-manager` threads this through to the mail-session delivery config the
same way the other delivery knobs flow. One global policy is acceptable for the
first cut (#133 permits it); per-domain can follow.

### Pipeline placement

The system Sieve runs at the existing Sieve stage (stage 2), on plaintext,
before at-rest encryption (stage 2.5) -- unchanged from where the per-user
script runs. `X-Spam-Flag` is a plaintext header, so it is readable there. The
encrypted-blob write paths (keep, fileinto, redirect :copy) are untouched.

## Bayes / spam-learn interaction

- **Server-filed Junk must not train.** rspamd already scored the message;
  training on it again would double-count and poison the model. Auto-filing to
  Junk in the delivery pipeline performs no IMAP `MOVE`, so it triggers no
  learn -- correct by construction. Keep it that way: the delivery path must
  never call rspamd learn.
- **Only user moves train.** imapd's `MOVE`-into-Junk trains spam and (the
  false-positive rescue) `MOVE`-out-of-Junk trains ham. That path is unchanged.
  Verify move-out-of-Junk trains ham as part of this work's test pass; it is the
  correction signal for our own false positives.

## Folder handling

`fileinto "Junk"` reaches `MaildirStore.DeliverToFolder` /`AppendToFolder`,
which call `ensureFolderMaildir` -- the Junk maildir is created on first use. No
separate auto-create step is needed. (`fileinto "INBOX"` is already treated as a
keep, not a folder named INBOX.)

## Tests (TDD)

Fail-without / pass-with, per the acceptance criteria in #133:

Prerequisite (smtpd):
- With `AddHeaders` on and a flagged result, the delivered bytes carry
  `X-Spam-Flag: YES` above `Received` (currently absent -- fails today).
- Clean result carries `X-Spam-Flag: NO`; `AddHeaders` off carries neither.

System Sieve (mail-session/deliver):
- `X-Spam-Flag: YES` + `FileSpamToJunk` on -> message lands in Junk, not INBOX.
- Clean mail (`X-Spam-Flag: NO` or absent) -> INBOX.
- Threshold boundary: the rule keys on the header value, so cover
  present-YES / present-NO / header-absent.
- `FileSpamToJunk` off -> flagged mail stays in INBOX (feature gate works).
- User script still runs for non-spam mail (system script took no action).
- Spam path does not run the user script (system script claimed the message).
- Delivery-time filing triggers no rspamd learn call.

Integration:
- End-to-end: smtpd stamps -> mail-session files to Junk, with the IDLE
  notification folder matching the actual destination.

## Sequencing

1. smtpd: stamp `checkResult.Headers` onto delivered/enqueued/forwarded bytes
   (prerequisite, self-contained commit; fixes the compute-and-discard gap and
   the lying IDLE notification).
2. deliver: `FileSpamToJunk` config + embedded default system script + the
   system-then-user composition in `runSieve`.
3. session-manager: thread `file_spam_to_junk` through to mail-session.
4. Docs: config reference for `file_spam_to_junk` and the deploy order
   (stamping must be live before enabling filing).

[#133]: https://github.com/infodancer/maildancer/issues/133
