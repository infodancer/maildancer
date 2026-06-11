package deliver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	gosieve "git.sr.ht/~emersion/go-sieve"
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
				return DeliverResponse{
					Result:    ResultRejected,
					Temporary: false,
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
	dlvr.parseSieve(domainName, localpart)

	// ── 4. Deliver to maildir ────────────────────────────────────────────────
	if dom.DeliveryAgent == nil {
		return DeliverResponse{
			Result:    ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("no delivery agent for domain %q", domainName),
		}, nil
	}

	envelope := msgstore.Envelope{
		From:           req.Sender,
		Recipients:     []string{req.Recipient},
		ClientHostname: req.ClientHostname,
		// Thread the already-forwarded flag through to MailDeliveryAgent so it
		// does not resolve forwarding rules a second time (1-hop enforcement).
		Forwarded: req.Forwarded,
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

// parseSieve loads and parses the user's .sieve script.
// Errors are logged but do not affect delivery -- fail-safe.
func (dlvr *Deliverer) parseSieve(domainName, localpart string) {
	path := filepath.Join(dlvr.cfg.DataPath(), domainName, "users", localpart, ".sieve")
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("opening sieve script", slog.String("path", path), slog.String("error", err.Error()))
		}
		return
	}
	defer func() { _ = f.Close() }()

	cmds, err := gosieve.Parse(f)
	if err != nil {
		slog.Warn("parsing sieve script", slog.String("path", path), slog.String("error", err.Error()))
		return
	}

	slog.Debug("sieve script parsed (execution not yet implemented)",
		slog.String("path", path),
		slog.Int("commands", len(cmds)))
}

// splitAddress splits an email address into localpart and domain.
func splitAddress(addr string) (localpart, domainName string) {
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return addr, ""
	}
	return addr[:i], addr[i+1:]
}
