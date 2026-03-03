// Package deliver orchestrates the full delivery pipeline: forwarding resolution,
// spam checking, sieve parsing, and final maildir write.
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
	"github.com/infodancer/maildancer/internal/mail-deliver/config"
	"github.com/infodancer/maildancer/internal/mail-deliver/rspamd"
	"github.com/infodancer/maildancer/internal/mail-deliver/protocol"
)

// Deliverer runs the delivery pipeline for a single message.
type Deliverer struct {
	cfg config.Config
	dp  *domain.FilesystemDomainProvider
}

// New creates a Deliverer from the given config.
// The caller must call Close() when done to release domain provider resources.
func New(cfg config.Config) (*Deliverer, error) {
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

// Deliver runs the full delivery pipeline and returns a DeliverResponse.
// An error is returned only for internal failures (I/O, programming errors);
// policy decisions (spam reject, forward) are expressed in the response.
func (dlvr *Deliverer) Deliver(ctx context.Context, req protocol.DeliverRequest, msg []byte) (protocol.DeliverResponse, error) {
	if len(req.Recipients) == 0 {
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: false,
			Reason:    "no recipients in envelope",
		}, nil
	}

	recipient := req.Recipients[0]
	localpart, domainName := splitAddress(recipient)

	dom := dlvr.dp.GetDomain(domainName)
	if dom == nil {
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("domain %q not configured", domainName),
		}, nil
	}

	// ── 1. Forwarding resolution ─────────────────────────────────────────────
	// Skipped when Forwarded=true to enforce the 1-hop limit.
	if !req.Forwarded && dom.AuthAgent != nil {
		if targets, ok := dom.AuthAgent.ResolveForward(ctx, localpart); ok {
			slog.Debug("forwarding message",
				slog.String("recipient", recipient),
				slog.Any("targets", targets))
			return protocol.DeliverResponse{
				Version:   protocol.Version,
				Result:    protocol.ResultRedirected,
				Addresses: targets,
			}, nil
		}
	}

	// ── 2. Spam check ────────────────────────────────────────────────────────
	spamCfg := dlvr.resolveSpamConfig(domainName, localpart)
	if spamCfg.IsEnabled() {
		resp, skip, err := dlvr.checkSpam(ctx, spamCfg, msg, req)
		if err != nil {
			// Rspamd unavailable — apply fail mode.
			slog.Warn("rspamd check failed", slog.String("error", err.Error()))
			switch spamCfg.GetFailMode() {
			case "reject":
				return protocol.DeliverResponse{
					Version:   protocol.Version,
					Result:    protocol.ResultRejected,
					Temporary: false,
					Reason:    "spam check unavailable",
				}, nil
			case "tempfail":
				return protocol.DeliverResponse{
					Version:   protocol.Version,
					Result:    protocol.ResultRejected,
					Temporary: true,
					Reason:    "spam check temporarily unavailable",
				}, nil
			// "open": fall through
			}
		} else if !skip {
			// Spam check returned a decision.
			return resp, nil
		}
	}

	// ── 3. Sieve script ──────────────────────────────────────────────────────
	// Parse the user's .sieve script. No actions are executed yet — this wires
	// up the parser so execution can be added incrementally without a format change.
	dlvr.parseSieve(domainName, localpart)

	// ── 4. Deliver to maildir ────────────────────────────────────────────────
	if dom.DeliveryAgent == nil {
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("no delivery agent for domain %q", domainName),
		}, nil
	}

	envelope := msgstore.Envelope{
		From:           req.Sender,
		Recipients:     req.Recipients,
		ClientHostname: req.ClientHostname,
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
		return protocol.DeliverResponse{}, fmt.Errorf("maildir delivery to %s: %w", recipient, err)
	}

	slog.Debug("message delivered", slog.String("recipient", recipient))
	return protocol.DeliverResponse{
		Version: protocol.Version,
		Result:  protocol.ResultDelivered,
	}, nil
}

// resolveSpamConfig builds an effective SpamConfig for the given domain/localpart
// by layering: global defaults ← domain spam.toml ← user spam.toml.
func (dlvr *Deliverer) resolveSpamConfig(domainName, localpart string) config.SpamConfig {
	effective := dlvr.cfg.Rspamd

	// Domain-level override: {domains_path}/{domain}/spam.toml
	domainSpam, err := config.LoadSpamConfig(
		filepath.Join(dlvr.cfg.DomainsPath, domainName, "spam.toml"),
	)
	if err != nil {
		slog.Warn("loading domain spam config", slog.String("domain", domainName), slog.String("error", err.Error()))
	} else {
		effective = effective.Merge(domainSpam)
	}

	// User-level override: {data_path}/{domain}/users/{localpart}/spam.toml
	userSpam, err := config.LoadSpamConfig(
		filepath.Join(dlvr.cfg.DataPath(), domainName, "users", localpart, "spam.toml"),
	)
	if err != nil {
		slog.Warn("loading user spam config", slog.String("user", localpart), slog.String("error", err.Error()))
	} else {
		effective = effective.Merge(userSpam)
	}

	return effective
}

// checkSpam runs rspamd and returns (response, passThrough, error).
// passThrough=true means the check passed and delivery should continue.
// passThrough=false means the response contains a reject/tempfail decision.
func (dlvr *Deliverer) checkSpam(ctx context.Context, spamCfg config.SpamConfig, msg []byte, req protocol.DeliverRequest) (protocol.DeliverResponse, bool, error) {
	client := rspamd.New(spamCfg.URL, spamCfg.Password, spamCfg.GetTimeout())
	result, err := client.Check(ctx, msg, rspamd.CheckOptions{
		From:       req.Sender,
		Recipients: req.Recipients,
		IP:         req.ClientIP,
		Helo:       req.ClientHostname,
	})
	if err != nil {
		return protocol.DeliverResponse{}, false, err
	}

	slog.Debug("rspamd result",
		slog.Float64("score", result.Score),
		slog.String("action", result.Action),
		slog.Bool("is_spam", result.IsSpam))

	// Apply threshold overrides, then fall back to rspamd's action.
	if spamCfg.RejectThreshold > 0 && result.Score >= spamCfg.RejectThreshold {
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: false,
			Reason:    fmt.Sprintf("spam score %.1f exceeds reject threshold %.1f", result.Score, spamCfg.RejectThreshold),
		}, false, nil
	}

	if spamCfg.TempFailThreshold > 0 && result.Score >= spamCfg.TempFailThreshold {
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("spam score %.1f exceeds tempfail threshold %.1f", result.Score, spamCfg.TempFailThreshold),
		}, false, nil
	}

	switch result.Action {
	case "reject":
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: false,
			Reason:    fmt.Sprintf("message rejected by rspamd (score %.1f)", result.Score),
		}, false, nil
	case "soft reject":
		return protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: true,
			Reason:    fmt.Sprintf("message deferred by rspamd (score %.1f)", result.Score),
		}, false, nil
	}

	// Accepted (no action / add header / greylist / etc.).
	return protocol.DeliverResponse{}, true, nil
}

// parseSieve loads and parses the user's .sieve script.
// Errors are logged but do not affect delivery — fail-safe.
// No sieve actions are executed yet; execution will be added incrementally.
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
// Returns ("", "") for addresses without an @ sign.
func splitAddress(addr string) (localpart, domainName string) {
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return addr, ""
	}
	return addr[:i], addr[i+1:]
}
