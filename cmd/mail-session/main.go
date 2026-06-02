package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/infodancer/maildancer/internal/mail-session/deliver"
	"github.com/infodancer/maildancer/internal/mail-session/grpcserver"
	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"github.com/pelletier/go-toml/v2"
)

// fileConfig is the TOML structure for [mail-session] in the shared config file.
type fileConfig struct {
	MailSession mailSessionConfig `toml:"mail-session"`
}

type mailSessionConfig struct {
	RescanInterval string `toml:"rescan_interval"`
}

// keyEnvelope is the JSON structure written to fd 3 by the spawning daemon.
// Using a versioned JSON envelope (rather than raw bytes) lets us add fields
// without a breaking protocol change — e.g. Algorithm, KeyID, Expires, or a
// Keys array for keyring support. When auth implements DeriveKeyPair it will
// encode this envelope; pop3d/imapd write a stub version for now.
// See: infodancer/infodancer/docs/encryption-design.md
type keyEnvelope struct {
	Version int    `json:"version"`
	Key     []byte `json:"key"` // 32-byte NaCl session key, base64-encoded
}

// maybeWrapWithDecryptingStore attempts to read a keyEnvelope from fd 3
// (ExtraFiles[0] as set by the spawning daemon). If fd 3 is present and
// contains a valid v1 envelope with a 32-byte key, the store is wrapped in a
// PassthroughDecryptingStore with the key applied; otherwise the store is
// returned unchanged (encryption not configured or fd 3 absent).
func maybeWrapWithDecryptingStore(underlying msgstore.MessageStore) msgstore.MessageStore {
	keyFile := os.NewFile(3, "key-pipe")
	var env keyEnvelope
	err := json.NewDecoder(keyFile).Decode(&env)
	_ = keyFile.Close()
	if err != nil || env.Version != 1 || len(env.Key) != 32 {
		// fd 3 absent, parse error, or unexpected envelope — use store as-is.
		if err != nil && !isErrBadFd(err) {
			slog.Warn("fd 3 key envelope invalid, skipping encryption", "error", err)
		}
		return underlying
	}
	ds := msgstore.NewPassthroughDecryptingStore(underlying)
	ds.SetSessionKey(env.Key)
	// Zero the local copy; ds holds the only in-memory key bytes.
	for i := range env.Key {
		env.Key[i] = 0
	}
	slog.Debug("session key loaded from fd 3", "version", env.Version)
	return ds
}

// isErrBadFd reports whether err is an os.PathError wrapping EBADF,
// which indicates fd 3 was not passed by the spawning daemon.
func isErrBadFd(err error) bool {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err == syscall.EBADF
	}
	return false
}

func main() {
	storeType := flag.String("type", "maildir", "message store type")
	basePath := flag.String("basepath", "", "path to store root (required)")
	rescanIntervalStr := flag.String("rescan-interval", "30s", "periodic rescan interval (0 or 0s = disabled)")
	configPath := flag.String("config", "", "path to TOML config file (optional; [mail-session] section)")

	// gRPC mode flags.
	mode := flag.String("mode", "daemon", "operating mode: daemon (long-lived gRPC) or oneshot (single delivery gRPC)")
	socketPath := flag.String("socket", "", "unix domain socket path (required)")
	idleTimeoutStr := flag.String("idle-timeout", "", "idle timeout before auto-shutdown (default: 30m for daemon, 60s for oneshot)")
	domainsPath := flag.String("domains-path", "", "path to domain config directory (required for delivery)")
	domainsDataPath := flag.String("domains-data-path", "", "path to domain data directory (defaults to domains-path)")
	mailbox := flag.String("mailbox", "", "user@domain identity (required)")
	flag.Parse()

	// Load config file if provided; CLI flags override.
	if *configPath != "" {
		var fc fileConfig
		data, err := os.ReadFile(*configPath)
		if err != nil {
			slog.Warn("failed to read config file", "path", *configPath, "error", err)
		} else if err := toml.Unmarshal(data, &fc); err != nil {
			slog.Warn("failed to parse config file", "path", *configPath, "error", err)
		} else {
			applyFileConfig(&fc, rescanIntervalStr)
		}
	}

	if *basePath == "" {
		slog.Error("--basepath is required")
		os.Exit(2)
	}

	if *mailbox == "" {
		slog.Error("--mailbox is required")
		os.Exit(2)
	}

	rescanInterval, err := parseDurationOrDisable(*rescanIntervalStr)
	if err != nil {
		slog.Error("invalid --rescan-interval", "value", *rescanIntervalStr, "error", err)
		os.Exit(2)
	}

	store, err := msgstore.Open(msgstore.StoreConfig{
		Type:     *storeType,
		BasePath: *basePath,
	})
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}

	// ── Encryption seam: fd 3 key pipe ───────────────────────────────────────
	sessionStore := maybeWrapWithDecryptingStore(store)
	// ─────────────────────────────────────────────────────────────────────────

	sess := session.New(sessionStore)
	if err := sess.Open(context.Background(), *mailbox); err != nil {
		slog.Error("open mailbox", "mailbox", *mailbox, "error", err)
		os.Exit(1)
	}

	runGRPC(sess, *mode, *socketPath, *idleTimeoutStr, *domainsPath, *domainsDataPath, rescanInterval)
}

// runGRPC starts mail-session in daemon or oneshot gRPC mode.
func runGRPC(sess *session.Session, mode, socketPath, idleTimeoutStr, domainsPath, domainsDataPath string, rescanInterval time.Duration) {
	if socketPath == "" {
		slog.Error("--socket is required")
		os.Exit(2)
	}

	// Determine idle timeout defaults.
	var idleTimeout time.Duration
	if idleTimeoutStr != "" {
		d, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			slog.Error("invalid --idle-timeout", "value", idleTimeoutStr, "error", err)
			os.Exit(2)
		}
		idleTimeout = d
	} else if mode == "daemon" {
		idleTimeout = 30 * time.Minute
	} else {
		idleTimeout = 60 * time.Second
	}

	// Set up delivery pipeline if domains-path is configured.
	var dlvr *deliver.Deliverer
	if domainsPath != "" {
		var err error
		dlvr, err = deliver.New(deliver.Config{
			DomainsPath:     domainsPath,
			DomainsDataPath: domainsDataPath,
		})
		if err != nil {
			slog.Error("delivery pipeline init", "error", err)
			os.Exit(1)
		}
		defer func() { _ = dlvr.Close() }()
	}

	srv := grpcserver.NewServer(grpcserver.Config{
		Session:        sess,
		Deliverer:      dlvr,
		IdleTimeout:    idleTimeout,
		RescanInterval: rescanInterval,
	})

	slog.Info("starting gRPC server",
		"mode", mode,
		"socket", socketPath,
		"idle_timeout", idleTimeout)

	if err := srv.Serve(socketPath); err != nil {
		slog.Error("gRPC server", "error", err)
		os.Exit(1)
	}
}

// applyFileConfig applies config file values only for flags that were not
// explicitly set on the command line.
func applyFileConfig(fc *fileConfig, rescanIntervalStr *string) {
	// Only apply if the flag wasn't explicitly provided.
	flagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "rescan-interval" {
			flagSet = true
		}
	})
	if !flagSet && fc.MailSession.RescanInterval != "" {
		*rescanIntervalStr = fc.MailSession.RescanInterval
	}
}

// parseDurationOrDisable parses a duration string, treating "0" and "0s" as disabled (returns 0).
func parseDurationOrDisable(s string) (time.Duration, error) {
	if s == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("negative duration %s", s)
	}
	return d, nil
}
