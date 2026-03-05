package smtp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/maildeliver"
)

// ExecDeliveryConfig configures an ExecDeliveryAgent.
type ExecDeliveryConfig struct {
	Cmd        string // absolute path to mail-deliver binary
	ConfigPath string // absolute path to smtpd config file (passed as --config)
	UID        int    // setuid target; 0 = no drop
	GID        int    // setgid target; 0 = no drop
}

// ExecDeliveryAgent implements msgstore.DeliveryAgent by spawning a mail-deliver
// subprocess for each message. This provides process isolation and enables
// privilege separation (the subprocess can drop to the mail user's uid/gid).
type ExecDeliveryAgent struct {
	cfg ExecDeliveryConfig
}

// NewExecDeliveryAgent creates a new ExecDeliveryAgent with the given config.
func NewExecDeliveryAgent(cfg ExecDeliveryConfig) *ExecDeliveryAgent {
	return &ExecDeliveryAgent{cfg: cfg}
}

// Deliver serialises the envelope as a JSON line, followed by the raw message
// bytes, and pipes both to a mail-deliver subprocess. Returns an error if the
// subprocess exits non-zero.
func (a *ExecDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	// Buffer the message so we can pipe it after the JSON header.
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("mail-deliver: reading message: %w", err)
	}

	req := maildeliver.DeliverRequest{
		Version:        maildeliver.Version,
		Sender:         envelope.From,
		Recipients:     envelope.Recipients,
		ClientHostname: envelope.ClientHostname,
		UID:            a.cfg.UID,
		GID:            a.cfg.GID,
	}
	if !envelope.ReceivedTime.IsZero() {
		req.ReceivedTime = envelope.ReceivedTime.Format(time.RFC3339)
	}
	if envelope.ClientIP != nil {
		req.ClientIP = envelope.ClientIP.String()
	}

	// ── Encryption seam ───────────────────────────────────────────────────────
	// When the recipient has encryption enabled, set req.EncryptionKeyHint to
	// the key fingerprint resolved via auth.KeyProvider using envelope.Recipients[0].
	// Deferred: real key lookup requires auth.KeyProvider integration.
	// See: infodancer/infodancer/docs/encryption-design.md
	// ─────────────────────────────────────────────────────────────────────────

	if envelope.SpamResult != nil {
		req.SpamScore = envelope.SpamResult.Score
		req.SpamAction = envelope.SpamResult.Action
		req.SpamChecker = envelope.SpamResult.Checker
	}

	jsonBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("mail-deliver: marshalling envelope: %w", err)
	}

	// stdin = JSON line + '\n' + message bytes
	var stdinBuf bytes.Buffer
	stdinBuf.Write(jsonBytes)
	stdinBuf.WriteByte('\n')
	stdinBuf.Write(msgBytes)

	cmd := exec.CommandContext(ctx, a.cfg.Cmd, "--config", a.cfg.ConfigPath)
	cmd.Stdin = &stdinBuf
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mail-deliver: %w: %s", err, output)
	}
	return nil
}
