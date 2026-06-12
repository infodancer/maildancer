package deliver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	_ "github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

// DeliverResult indicates the outcome of a delivery attempt.
type DeliverResult int

const (
	// ResultDelivered means the message was successfully written to the maildir.
	ResultDelivered DeliverResult = iota
	// ResultRejected means delivery was refused.
	ResultRejected
	// ResultRedirected means the message should be delivered to different addresses.
	ResultRedirected
)

// DeliverResponse holds the outcome of a delivery pipeline run.
type DeliverResponse struct {
	Result            DeliverResult
	Temporary         bool
	Reason            string
	RedirectAddresses []string
}

// DeliverRequest holds the envelope information for delivery.
type DeliverRequest struct {
	Sender            string
	Recipient         string
	ClientIP          string
	ClientHostname    string
	Forwarded         bool
	EncryptionKeyHint string
	ReceivedTime      string
}

// Deliverer runs the delivery pipeline for a single message.
type Deliverer struct {
	cfg Config
	dp  *domain.FilesystemDomainProvider
}

// New creates a Deliverer from the given config.
// The caller must call Close() when done to release domain provider resources.
func New(cfg Config) (*Deliverer, error) {
	if cfg.DomainsPath == "" {
		return nil, errors.New("domains_path is required")
	}

	dp := domain.NewFilesystemDomainProvider(cfg.DomainsPath, nil)
	if cfg.DomainsDataPath != "" {
		dp = dp.WithDataPath(cfg.DomainsDataPath)
	}
	dp = dp.WithDefaults(domain.DomainConfig{
		Auth: domain.DomainAuthConfig{
			Type:              "passwd",
			CredentialBackend: "passwd",
			KeyBackend:        "keys",
		},
		MsgStore: domain.DomainMsgStoreConfig{
			Type:     "maildir",
			BasePath: "users",
		},
	})

	return &Deliverer{cfg: cfg, dp: dp}, nil
}

// Close releases resources held by the domain provider.
func (dlvr *Deliverer) Close() error {
	return dlvr.dp.Close()
}

// Deliver runs the full 5-stage delivery pipeline.
// An error is returned only for internal failures; policy decisions are in the response.
func (dlvr *Deliverer) Deliver(ctx context.Context, req DeliverRequest, msg []byte) (DeliverResponse, error) {
	if req.Recipient == "" {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: false,
			Reason:    "no recipient specified",
		}, nil
	}

	localpart, domainName := splitAddress(req.Recipient)

	// Reject addresses with path-traversal characters.
	if localpart == "" || domainName == "" ||
		strings.ContainsAny(localpart, "/\\") || strings.ContainsAny(domainName, "/\\") ||
		strings.Contains(localpart, "..") || strings.Contains(domainName, "..") {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: false,
			Reason:    "invalid recipient address",
		}, nil
	}

	dom := dlvr.dp.GetDomain(domainName)
	if dom == nil {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("domain not found: %q", domainName),
		}, nil
	}

	// ── 1. Forwarding resolution ─────────────────────────────────────────────
	if !req.Forwarded && dom.AuthAgent != nil {
		if targets, ok := dom.AuthAgent.ResolveForward(ctx, localpart); ok {
			if len(targets) > 1 {
				// A multi-target forward is a configuration error: forwarding is
				// strictly 1:1. Temp-fail (not perm-fail) so the sending MTA holds
				// and retries while the admin fixes the misconfiguration; the
				// sending MTA's own retry window is the eventual permanent backstop.
				// We deliberately do NOT build stateful temp->perm escalation here.
				slog.Error("forwarding misconfiguration: multiple forward targets configured (1:1 required)",
					slog.String("recipient", req.Recipient),
					slog.Int("target_count", len(targets)))
				return DeliverResponse{
					Result:    ResultRejected,
					Temporary: true,
					Reason:    fmt.Sprintf("forwarding misconfiguration: only one forward destination allowed, %d configured", len(targets)),
				}, nil
			}
			slog.Debug("forwarding message",
				slog.String("recipient", req.Recipient),
				slog.String("target", targets[0]))
			return DeliverResponse{
				Result:            ResultRedirected,
				RedirectAddresses: targets,
			}, nil
		}
	}

	// ── 2. Per-domain size check ─────────────────────────────────────────────
	if dom.MaxMessageSize > 0 && int64(len(msg)) > dom.MaxMessageSize {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: false,
			Reason:    "message too large",
		}, nil
	}

	// ── 3. Sieve script ──────────────────────────────────────────────────────
	// A script decides the message's fate (fileinto, redirect, discard,
	// reject, keep). No script -- or any script failure -- falls through to
	// stage 4 (implicit keep). Sieve evaluates the plaintext message.
	outcome, sieveRan := dlvr.runSieve(ctx, dom, req, msg)

	// ── 3.5. At-rest encryption ──────────────────────────────────────────────
	// After Sieve (which needs plaintext), before any write, so that every
	// write path below -- keep, fileinto, redirect :copy -- stores the same
	// encrypted blob. Fail-closed: a requested encryption that cannot be
	// performed temp-fails instead of writing plaintext.
	writeMsg, encInfo, encReject := dlvr.maybeEncrypt(ctx, dom, req, msg)
	if encReject != nil {
		return *encReject, nil
	}

	if sieveRan {
		return dlvr.applySieve(ctx, dom, req, outcome, writeMsg, encInfo)
	}

	// ── 4. Deliver to maildir ────────────────────────────────────────────────
	return dlvr.deliverLocal(ctx, dom, req, writeMsg, encInfo)
}

// deliverLocal is the final delivery stage: it hands the message to the
// domain's delivery agent for a normal mailbox write (including subaddress
// folder routing). Used both as the default pipeline tail and as the keep
// path after sieve execution. msg is the bytes to store -- already encrypted
// when encInfo is non-nil.
func (dlvr *Deliverer) deliverLocal(ctx context.Context, dom *domain.Domain, req DeliverRequest, msg []byte, encInfo *msgstore.EncryptionInfo) (DeliverResponse, error) {
	if dom.DeliveryAgent == nil {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("no delivery agent for domain %q", dom.Name),
		}, nil
	}

	envelope := msgstore.Envelope{
		From:           req.Sender,
		Recipients:     []string{req.Recipient},
		ClientHostname: req.ClientHostname,
		// Thread the already-forwarded flag through to MailDeliveryAgent so it
		// does not resolve forwarding rules a second time (1-hop enforcement).
		Forwarded:  req.Forwarded,
		Encryption: encInfo,
	}
	if req.ReceivedTime != "" {
		if t, err := time.Parse(time.RFC3339, req.ReceivedTime); err == nil {
			envelope.ReceivedTime = t
		}
	}
	if req.ClientIP != "" {
		envelope.ClientIP = net.ParseIP(req.ClientIP)
	}

	if err := dom.DeliveryAgent.Deliver(ctx, envelope, bytes.NewReader(msg)); err != nil {
		return DeliverResponse{}, fmt.Errorf("maildir delivery to %s: %w", req.Recipient, err)
	}

	slog.Debug("message delivered", slog.String("recipient", req.Recipient))
	return DeliverResponse{
		Result: ResultDelivered,
	}, nil
}

// splitAddress splits an email address into localpart and domain.
func splitAddress(addr string) (localpart, domainName string) {
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return addr, ""
	}
	return addr[:i], addr[i+1:]
}
