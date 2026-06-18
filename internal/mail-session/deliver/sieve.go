package deliver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	sieve "github.com/foxcpp/go-sieve"
	"github.com/foxcpp/go-sieve/interp"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
)

// maxSieveScriptSize caps how much of a user's .sieve script is read.
// Scripts over the cap are ignored (fail-safe to implicit keep). The
// interpreter's own limits (token count, nesting depth, redirect count)
// come from sieve.DefaultOptions.
const maxSieveScriptSize = 256 * 1024

// fileintoTarget is a folder delivery requested by a fileinto action.
type fileintoTarget struct {
	folder string
	flags  []string
}

// sieveOutcome is the digested result of executing a Sieve script.
type sieveOutcome struct {
	rejectReason string // non-empty if the script rejected the message
	fileinto     []fileintoTarget
	keep         bool // explicit or implicit keep
	keepFlags    []string
	redirects    []string
}

// sievePolicy enforces redirect restrictions during script execution.
// A disallowed redirect is silently skipped by the interpreter, which
// preserves implicit keep -- the message stays in the local mailbox.
type sievePolicy struct {
	forwarded bool   // message was already forwarded once (1-hop rule)
	recipient string // envelope recipient, to suppress self-redirects
}

func (p sievePolicy) RedirectAllowed(_ context.Context, _ *interp.RuntimeData, addr string) (bool, error) {
	if p.forwarded {
		slog.Debug("sieve redirect suppressed: message already forwarded (1-hop rule)",
			slog.String("recipient", p.recipient),
			slog.String("target", addr))
		return false, nil
	}
	if strings.EqualFold(addr, p.recipient) {
		slog.Debug("sieve redirect to self suppressed",
			slog.String("recipient", p.recipient))
		return false, nil
	}
	if _, err := mail.ParseAddress(addr); err != nil {
		slog.Warn("sieve redirect to unparseable address suppressed",
			slog.String("recipient", p.recipient),
			slog.String("target", addr),
			slog.String("error", err.Error()))
		return false, nil
	}
	return true, nil
}

// runSieve loads and executes the recipient's Sieve script.
//
// Returns (nil, false) when there is no script or when loading, parsing, or
// execution fails -- the caller falls through to normal delivery (RFC 5228
// section 2.10.6: implicit keep on error). Errors are logged, never fatal.
func (dlvr *Deliverer) runSieve(ctx context.Context, dom *domain.Domain, req DeliverRequest, msg []byte) (*sieveOutcome, bool) {
	provider, ok := dom.MessageStore.(msgstore.SieveScriptProvider)
	if !ok {
		return nil, false
	}

	mailbox := msgstore.ParseRecipient(req.Recipient).Address
	rc, err := provider.SieveScript(ctx, mailbox)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("opening sieve script",
				slog.String("msgid", req.MsgID),
				slog.String("mailbox", mailbox),
				slog.String("error", err.Error()))
		}
		return nil, false
	}
	defer func() { _ = rc.Close() }()

	raw, err := io.ReadAll(io.LimitReader(rc, maxSieveScriptSize+1))
	if err != nil {
		slog.Warn("reading sieve script",
			slog.String("msgid", req.MsgID),
			slog.String("mailbox", mailbox),
			slog.String("error", err.Error()))
		return nil, false
	}
	if len(raw) > maxSieveScriptSize {
		slog.Warn("sieve script exceeds size cap, ignoring",
			slog.String("msgid", req.MsgID),
			slog.String("mailbox", mailbox),
			slog.Int("cap_bytes", maxSieveScriptSize))
		return nil, false
	}

	script, err := sieve.Load(bytes.NewReader(raw), sieve.DefaultOptions())
	if err != nil {
		slog.Warn("parsing sieve script",
			slog.String("msgid", req.MsgID),
			slog.String("mailbox", mailbox),
			slog.String("error", err.Error()))
		return nil, false
	}

	hdr, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(msg))).ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		slog.Warn("parsing message headers for sieve",
			slog.String("msgid", req.MsgID),
			slog.String("mailbox", mailbox),
			slog.String("error", err.Error()))
		return nil, false
	}

	data := sieve.NewRuntimeData(script,
		sievePolicy{forwarded: req.Forwarded, recipient: req.Recipient},
		interp.EnvelopeStatic{From: req.Sender, To: req.Recipient},
		interp.MessageStatic{Size: len(msg), Header: hdr, RawMessage: msg})

	if err := script.Execute(ctx, data); err != nil {
		slog.Warn("executing sieve script",
			slog.String("msgid", req.MsgID),
			slog.String("mailbox", mailbox),
			slog.String("error", err.Error()))
		return nil, false
	}

	outcome := digestActions(data)
	slog.Debug("sieve script executed",
		slog.String("msgid", req.MsgID),
		slog.String("mailbox", mailbox),
		slog.Int("fileinto", len(outcome.fileinto)),
		slog.Int("redirects", len(outcome.redirects)),
		slog.Bool("keep", outcome.keep),
		slog.Bool("reject", outcome.rejectReason != ""))
	return outcome, true
}

// digestActions reduces the interpreter's run to a sieveOutcome. The
// interpreter already deduplicates fileinto targets. Keep is read from the
// runtime fields rather than the action stream: a script ending in "stop"
// returns from Execute before the implicit-keep action is appended, but the
// ImplicitKeep field still reflects whether any action cancelled it.
func digestActions(data *interp.RuntimeData) *sieveOutcome {
	outcome := &sieveOutcome{}
	for _, action := range data.AppliedActions {
		switch a := action.(type) {
		case interp.ActionKeep:
			outcome.keep = true
			outcome.keepFlags = a.Flags
		case interp.ActionFileInto:
			// fileinto "INBOX" is a keep, not a folder named ".INBOX".
			if strings.EqualFold(a.Mailbox, "INBOX") {
				outcome.keep = true
				outcome.keepFlags = a.Flags
				continue
			}
			outcome.fileinto = append(outcome.fileinto, fileintoTarget{folder: a.Mailbox, flags: a.Flags})
		case interp.ActionRedirect:
			outcome.redirects = append(outcome.redirects, a.Address)
		case interp.ActionReject:
			outcome.rejectReason = a.Reason
		case interp.ActionEReject:
			outcome.rejectReason = a.Reason
		case interp.ActionDiscard:
			// Discard only cancels implicit keep; nothing to record.
		}
	}
	if data.ImplicitKeep && !outcome.keep {
		outcome.keep = true
		outcome.keepFlags = data.Flags
	}
	return outcome
}

// applySieve carries out a sieveOutcome: rejects, folder deliveries, keep,
// and redirect propagation. msg is the bytes to store -- already encrypted
// when encInfo is non-nil (Sieve itself evaluated the plaintext earlier).
// An error is returned only for internal storage failures (temp-fail at the
// SMTP layer, same as the normal delivery path).
func (dlvr *Deliverer) applySieve(ctx context.Context, dom *domain.Domain, req DeliverRequest, outcome *sieveOutcome, msg []byte, encInfo *msgstore.EncryptionInfo) (DeliverResponse, error) {
	// RFC 5429: reject is incompatible with actions that deliver the
	// message; when a script produces both, the reject wins.
	if outcome.rejectReason != "" {
		if outcome.keep || len(outcome.fileinto) > 0 || len(outcome.redirects) > 0 {
			slog.Warn("sieve script combined reject with delivery actions; rejecting",
				slog.String("msgid", req.MsgID),
				slog.String("recipient", req.Recipient))
		}
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: false,
			Reason:    outcome.rejectReason,
		}, nil
	}

	mailbox := msgstore.ParseRecipient(req.Recipient).Address

	for _, target := range outcome.fileinto {
		if err := dlvr.deliverToFolder(ctx, dom, req, mailbox, target, msg, encInfo); err != nil {
			return DeliverResponse{}, err
		}
	}

	if outcome.keep {
		if len(outcome.keepFlags) > 0 {
			err := dlvr.deliverToFolder(ctx, dom, req, mailbox,
				fileintoTarget{folder: "INBOX", flags: outcome.keepFlags}, msg, encInfo)
			if err != nil {
				return DeliverResponse{}, err
			}
		} else {
			// Flagless keep goes through the standard delivery path so
			// subaddress folder routing still applies.
			if resp, err := dlvr.deliverLocal(ctx, dom, req, msg, encInfo); err != nil || resp.Result != ResultDelivered {
				return resp, err
			}
		}
	}

	if len(outcome.redirects) > 0 {
		return DeliverResponse{
			Result:            ResultRedirected,
			RedirectAddresses: dedupeFold(outcome.redirects),
		}, nil
	}
	return DeliverResponse{Result: ResultDelivered}, nil
}

// deliverToFolder writes the message to a folder in the recipient's mailbox.
// Deliveries carrying imap4flags go through AppendToFolder (which accepts
// flags); flagless deliveries use DeliverToFolder. msg is the bytes to
// store -- already encrypted when encInfo is non-nil.
func (dlvr *Deliverer) deliverToFolder(ctx context.Context, dom *domain.Domain, req DeliverRequest, mailbox string, target fileintoTarget, msg []byte, encInfo *msgstore.EncryptionInfo) error {
	folderStore, ok := dom.MessageStore.(msgstore.FolderStore)
	if !ok {
		// No folder support in this store: fall back to the inbox rather
		// than losing the message.
		slog.Warn("sieve fileinto unsupported by message store, delivering to inbox",
			slog.String("msgid", req.MsgID),
			slog.String("recipient", req.Recipient),
			slog.String("folder", target.folder))
		_, err := dlvr.deliverLocal(ctx, dom, req, msg, encInfo)
		return err
	}

	if len(target.flags) > 0 {
		date := time.Now()
		if req.ReceivedTime != "" {
			if t, err := time.Parse(time.RFC3339, req.ReceivedTime); err == nil {
				date = t
			}
		}
		_, err := folderStore.AppendToFolder(ctx, mailbox, target.folder, bytes.NewReader(msg), target.flags, date)
		return err
	}
	if strings.EqualFold(target.folder, "INBOX") {
		_, err := dlvr.deliverLocal(ctx, dom, req, msg, encInfo)
		return err
	}
	return folderStore.DeliverToFolder(ctx, mailbox, target.folder, bytes.NewReader(msg))
}

// dedupeFold removes case-insensitive duplicates, preserving order.
func dedupeFold(addrs []string) []string {
	seen := make(map[string]bool, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		key := strings.ToLower(a)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	return out
}
