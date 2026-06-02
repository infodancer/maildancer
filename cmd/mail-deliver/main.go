// Command mail-deliver is the privilege-separated delivery agent for the
// infodancer mail stack. It is spawned by smtpd (or any other dispatcher)
// as uid=recipient-user, gid=domain, with the dispatcher having set
// SysProcAttr.Credential before exec.
//
// Wire format:
//
//	stdin:  JSON-encoded DeliverRequest (newline-terminated), then raw RFC 5322 message bytes until EOF.
//	stdout: JSON-encoded DeliverResponse (newline-terminated), written before exit.
//	stderr: log output only.
//
// Exit codes:
//
//	0: response written successfully (check DeliverResponse.Result for the outcome).
//	1: fatal error before a response could be written.
//
// See github.com/infodancer/maildancer/internal/mail-deliver/protocol for the wire types.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/mail-deliver/config"
	"github.com/infodancer/maildancer/internal/mail-deliver/deliver"
	mderrors "github.com/infodancer/maildancer/internal/mail-deliver/errors"
	"github.com/infodancer/maildancer/internal/mail-deliver/protocol"
)

func main() {
	if err := run(); err != nil {
		slog.Error("mail-deliver", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "", "path to shared TOML config file (required)")
	flag.Parse()

	if *cfgPath == "" {
		return fmt.Errorf("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Read JSON envelope from the first line of stdin.
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return fmt.Errorf("reading envelope: %w", err)
	}

	var req protocol.DeliverRequest
	if err := json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &req); err != nil {
		return fmt.Errorf("parsing envelope: %w", err)
	}
	if req.Version != protocol.Version {
		return fmt.Errorf("unsupported envelope version %d (want %d)", req.Version, protocol.Version)
	}

	// Read the message body (remainder of stdin after the JSON line).
	// Enforce a maximum size to prevent OOM from unbounded input.
	maxSize := cfg.MaxMessageSize
	if maxSize <= 0 {
		maxSize = 50 * 1024 * 1024 // default 50 MiB
	}
	msg, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}
	if int64(len(msg)) > maxSize {
		return writeResponse(protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: false,
			Reason:    mderrors.ErrMessageTooLarge.Error(),
		})
	}

	dlvr, err := deliver.New(cfg)
	if err != nil {
		return fmt.Errorf("initialising deliverer: %w", err)
	}
	defer func() { _ = dlvr.Close() }()

	deliveryTimeout := 60 * time.Second
	if cfg.DeliveryTimeout != "" {
		if d, err := time.ParseDuration(cfg.DeliveryTimeout); err == nil {
			deliveryTimeout = d
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
	defer cancel()

	resp, err := dlvr.Deliver(ctx, req, msg)
	if err != nil {
		// Internal error — write a temporary-failure response so the caller
		// can return a 4xx to the sender rather than silently losing the message.
		resp = protocol.DeliverResponse{
			Version:   protocol.Version,
			Result:    protocol.ResultRejected,
			Temporary: true,
			Reason:    err.Error(),
		}
		slog.Error("delivery error", slog.String("error", err.Error()))
	}

	return writeResponse(resp)
}

// writeResponse encodes resp as a JSON line on stdout.
func writeResponse(resp protocol.DeliverResponse) error {
	out, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encoding response: %w", err)
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", out)
	return err
}
