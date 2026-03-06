// Command mail-deliver receives a message delivery request via stdin and writes
// it to a maildir. It is invoked as a subprocess by smtpd when deliver_cmd is
// configured, providing process isolation and optional privilege separation.
//
// Wire format: JSON envelope on stdin line 1 (newline-terminated), followed by
// raw RFC 5322 message bytes until EOF.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	_ "github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/maildeliver"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mail-deliver:", err)
		os.Exit(1)
	}
}

func run() error {
	flags := config.ParseFlags()
	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Read JSON envelope from the first line of stdin.
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return fmt.Errorf("reading envelope: %w", err)
	}

	var req maildeliver.DeliverRequest
	if err := json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &req); err != nil {
		return fmt.Errorf("parsing envelope: %w", err)
	}
	if req.Version != maildeliver.Version {
		return fmt.Errorf("unsupported envelope version %d (want %d)", req.Version, maildeliver.Version)
	}
	if len(req.Recipients) == 0 {
		return fmt.Errorf("no recipients in envelope")
	}

	// Read the message body (rest of stdin, after the JSON line).
	msgBytes, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	// Drop privileges before touching any maildir files.
	// GID must be set before UID (setting UID first would drop the ability to setgid).
	if req.GID > 0 {
		if err := syscall.Setresgid(req.GID, req.GID, req.GID); err != nil {
			return fmt.Errorf("setresgid(%d): %w", req.GID, err)
		}
	}
	if req.UID > 0 {
		if err := syscall.Setresuid(req.UID, req.UID, req.UID); err != nil {
			return fmt.Errorf("setresuid(%d): %w", req.UID, err)
		}
	}

	// Reconstruct the envelope for the delivery agent.
	envelope := msgstore.Envelope{
		From:           req.Sender,
		Recipients:     req.Recipients,
		ClientHostname: req.ClientHostname,
	}
	if req.ReceivedTime != "" {
		if t, parseErr := time.Parse(time.RFC3339, req.ReceivedTime); parseErr == nil {
			envelope.ReceivedTime = t
		}
	}
	if req.ClientIP != "" {
		envelope.ClientIP = net.ParseIP(req.ClientIP)
	}
	if req.SpamAction != "" {
		envelope.SpamResult = &msgstore.SpamResult{
			Score:   req.SpamScore,
			Action:  req.SpamAction,
			Checker: req.SpamChecker,
		}
	}

	// Build global delivery agent from config (fallback when no per-domain config).
	var globalAgent msgstore.DeliveryAgent
	if cfg.Delivery.Type != "" {
		store, err := msgstore.Open(msgstore.StoreConfig{
			Type:     cfg.Delivery.Type,
			BasePath: cfg.Delivery.BasePath,
			Options:  cfg.Delivery.Options,
		})
		if err != nil {
			return fmt.Errorf("opening delivery store: %w", err)
		}
		globalAgent = store
	}

	// Build domain provider for per-domain delivery (same defaults as stack.go).
	var dp *domain.FilesystemDomainProvider
	if cfg.DomainsPath != "" {
		p := domain.NewFilesystemDomainProvider(cfg.DomainsPath, nil)
		if cfg.DomainsDataPath != "" {
			p = p.WithDataPath(cfg.DomainsDataPath)
		}
		dp = p.WithDefaults(domain.DomainConfig{
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
		defer dp.Close() //nolint:errcheck
	}

	ctx := context.Background()

	// Deliver to each recipient, using per-domain agent when available.
	for _, recipient := range req.Recipients {
		agent := globalAgent
		if dp != nil {
			domainName := extractDomain(recipient)
			if domainName != "" {
				if d := dp.GetDomain(domainName); d != nil && d.DeliveryAgent != nil {
					agent = d.DeliveryAgent
				}
			}
		}
		if agent == nil {
			return fmt.Errorf("no delivery agent for recipient %s", recipient)
		}

		single := msgstore.Envelope{
			From:           envelope.From,
			Recipients:     []string{recipient},
			ReceivedTime:   envelope.ReceivedTime,
			ClientIP:       envelope.ClientIP,
			ClientHostname: envelope.ClientHostname,
		}
		if err := agent.Deliver(ctx, single, bytes.NewReader(msgBytes)); err != nil {
			return fmt.Errorf("delivering to %s: %w", recipient, err)
		}
	}

	return nil
}

func extractDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
