package smtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/infodancer/maildancer/internal/mail-session/client"
	"github.com/infodancer/maildancer/msgstore"
)

// GrpcDeliveryConfig configures a GrpcDeliveryAgent.
type GrpcDeliveryConfig struct {
	// MailSessionCmd is the absolute path to the mail-session binary.
	MailSessionCmd string

	// BasePath is the base path for the message store (passed as --basepath).
	BasePath string

	// StoreType is the store backend type (passed as --type, defaults to "maildir").
	StoreType string

	// DomainsPath is the domains config directory (passed as --domains-path).
	DomainsPath string

	// DomainsDataPath is the domains data directory (passed as --domains-data-path).
	DomainsDataPath string

	// UID is the setuid target for the mail-session subprocess (0 = no drop).
	UID int

	// GID is the setgid target for the mail-session subprocess (0 = no drop).
	GID int

	// Logger is the logger for delivery diagnostics.
	Logger *slog.Logger
}

// GrpcDeliveryAgent implements msgstore.DeliveryAgent by spawning a
// mail-session subprocess in oneshot gRPC mode for each delivery.
//
// For each message, it:
//  1. Creates a temp unix socket path
//  2. Spawns mail-session --mode=oneshot with the recipient's mailbox
//  3. Waits for "READY\n" on stdout (socket is listening)
//  4. Connects via the mail-session client library
//  5. Calls Deliver() with structured metadata and streaming body
//  6. Returns structured results including redirect addresses
type GrpcDeliveryAgent struct {
	cfg GrpcDeliveryConfig
}

// NewGrpcDeliveryAgent creates a new GrpcDeliveryAgent.
func NewGrpcDeliveryAgent(cfg GrpcDeliveryConfig) *GrpcDeliveryAgent {
	if cfg.StoreType == "" {
		cfg.StoreType = "maildir"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &GrpcDeliveryAgent{cfg: cfg}
}

// Deliver spawns a mail-session oneshot subprocess for the recipient and
// streams the message via gRPC. Returns an error if delivery fails.
func (a *GrpcDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if len(envelope.Recipients) == 0 {
		return fmt.Errorf("grpc delivery: no recipients")
	}

	// Single recipient per delivery (enforced by smtpd session).
	recipient := envelope.Recipients[0]

	// Extract mailbox name from recipient address (local part + domain).
	mailbox := recipient
	if idx := strings.LastIndex(mailbox, "@"); idx >= 0 {
		// Use just the local part for the mailbox name.
		// mail-session resolves the domain from --domains-path.
		mailbox = mailbox[:idx]
	}

	// Create a temp directory for the socket.
	tmpDir, err := os.MkdirTemp("", "mail-session-*")
	if err != nil {
		return fmt.Errorf("grpc delivery: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "session.sock")

	// Build the mail-session command.
	args := []string{
		"--mode=oneshot",
		"--socket=" + socketPath,
		"--mailbox=" + recipient,
		"--basepath=" + a.cfg.BasePath,
		"--type=" + a.cfg.StoreType,
		"--idle-timeout=60s",
	}
	if a.cfg.DomainsPath != "" {
		args = append(args, "--domains-path="+a.cfg.DomainsPath)
	}
	if a.cfg.DomainsDataPath != "" {
		args = append(args, "--domains-data-path="+a.cfg.DomainsDataPath)
	}

	cmd := exec.CommandContext(ctx, a.cfg.MailSessionCmd, args...)

	// Set up privilege drop if configured.
	if a.cfg.UID != 0 || a.cfg.GID != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(a.cfg.UID),
				Gid: uint32(a.cfg.GID),
			},
		}
	}

	// Capture stdout for READY signal.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("grpc delivery: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("grpc delivery: start mail-session: %w", err)
	}

	// Wait for READY signal with timeout.
	readyCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				readyCh <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			readyCh <- fmt.Errorf("reading stdout: %w", err)
		} else {
			readyCh <- fmt.Errorf("mail-session exited without READY signal")
		}
	}()

	readyTimeout := 10 * time.Second
	select {
	case err := <-readyCh:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("grpc delivery: %w", err)
		}
	case <-time.After(readyTimeout):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("grpc delivery: timed out waiting for READY")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("grpc delivery: context cancelled: %w", ctx.Err())
	}

	// Connect to the gRPC socket.
	dc, err := client.DialDelivery(socketPath)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("grpc delivery: dial: %w", err)
	}
	defer dc.Close()

	// Build delivery metadata.
	meta := client.DeliveryMetadata{
		Sender:    envelope.From,
		Recipient: recipient,
	}
	if envelope.ClientIP != nil {
		meta.ClientIP = envelope.ClientIP.String()
	}
	meta.ClientHostname = envelope.ClientHostname
	if !envelope.ReceivedTime.IsZero() {
		meta.ReceivedTime = envelope.ReceivedTime.Format(time.RFC3339)
	}

	// Call Deliver.
	resp, err := dc.Deliver(ctx, meta, message)
	if err != nil {
		a.cfg.Logger.Error("grpc delivery failed",
			slog.String("recipient", recipient),
			slog.String("error", err.Error()))
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("grpc delivery: deliver RPC: %w", err)
	}

	// Close the client to let the subprocess shut down cleanly.
	_ = dc.Close()

	// Wait for the subprocess to exit.
	if err := cmd.Wait(); err != nil {
		a.cfg.Logger.Debug("mail-session subprocess exited with error",
			slog.String("error", err.Error()))
	}

	// Handle delivery result.
	switch resp.Result {
	case client.Delivered:
		a.cfg.Logger.Debug("grpc delivery complete",
			slog.String("recipient", recipient))
		return nil

	case client.Rejected:
		code := "550"
		if resp.Temporary {
			code = "451"
		}
		a.cfg.Logger.Debug("grpc delivery rejected",
			slog.String("recipient", recipient),
			slog.String("code", code),
			slog.String("reason", resp.Reason))
		return fmt.Errorf("delivery rejected (%s): %s", code, resp.Reason)

	case client.Redirected:
		a.cfg.Logger.Info("grpc delivery redirected",
			slog.String("recipient", recipient),
			slog.Int("redirect_count", len(resp.RedirectAddresses)),
			slog.String("addresses", joinAddresses(resp.RedirectAddresses)))
		// Return a typed error so callers can extract redirect addresses.
		return &RedirectError{
			Addresses: resp.RedirectAddresses,
			Temporary: resp.Temporary,
		}

	default:
		return fmt.Errorf("grpc delivery: unknown result %d", resp.Result)
	}
}

// RedirectError indicates the delivery was redirected to other addresses.
// Callers should re-deliver the message to the specified addresses.
type RedirectError struct {
	Addresses []string
	Temporary bool
}

func (e *RedirectError) Error() string {
	return "delivery redirected to " + strconv.Itoa(len(e.Addresses)) + " address(es)"
}

// joinAddresses joins addresses with commas for logging.
func joinAddresses(addrs []string) string {
	if len(addrs) == 0 {
		return "(none)"
	}
	return strings.Join(addrs, ", ")
}
