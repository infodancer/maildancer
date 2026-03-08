package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	mserrors "github.com/infodancer/maildancer/internal/mail-session/errors"
	"github.com/infodancer/maildancer/internal/mail-session/deliver"
	"github.com/infodancer/maildancer/internal/mail-session/grpcserver"
	"github.com/infodancer/maildancer/internal/mail-session/protocol"
	"github.com/infodancer/maildancer/internal/mail-session/rspamd"
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

// commandResult carries a parsed command (and optional payload) or error from
// the reader goroutine. For APPEND commands, the body bytes are read by the
// reader goroutine to avoid a data race on the underlying bufio.Reader.
type commandResult struct {
	cmd  *protocol.Command
	data []byte // non-nil for APPEND (body bytes)
	err  error
}

func main() {
	storeType := flag.String("type", "maildir", "message store type")
	basePath := flag.String("basepath", "", "path to store root (required)")
	rspamdURL := flag.String("rspamd", "", "rspamd controller URL (e.g. http://rspamd:11334); empty disables learning")
	junkFolder := flag.String("junk-folder", "Junk", "name of the Junk/Spam folder for rspamd learning")
	rspamdUser := flag.String("user", "", "user@domain identity passed to rspamd as User: header for per-user Bayes")
	maxMessageSize := flag.Int64("max-message-size", 50*1024*1024, "maximum message size in bytes for rspamd learning (0 = use default)")
	rescanIntervalStr := flag.String("rescan-interval", "30s", "periodic rescan interval (0 or 0s = disabled)")
	configPath := flag.String("config", "", "path to TOML config file (optional; [mail-session] section)")

	// gRPC mode flags.
	mode := flag.String("mode", "pipe", "operating mode: pipe (default), daemon (long-lived gRPC), oneshot (single delivery gRPC)")
	socketPath := flag.String("socket", "", "unix domain socket path (required for daemon/oneshot modes)")
	idleTimeoutStr := flag.String("idle-timeout", "", "idle timeout before auto-shutdown (default: 30m for daemon, 60s for oneshot)")
	domainsPath := flag.String("domains-path", "", "path to domain config directory (required for delivery)")
	domainsDataPath := flag.String("domains-data-path", "", "path to domain data directory (defaults to domains-path)")
	mailbox := flag.String("mailbox", "", "user@domain identity (required for daemon/oneshot gRPC modes)")
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

	// ── Mode dispatch ────────────────────────────────────────────────────────
	switch *mode {
	case "daemon", "oneshot":
		if *mailbox == "" {
			slog.Error("--mailbox is required for " + *mode + " mode")
			os.Exit(2)
		}
		if err := sess.Open(context.Background(), *mailbox); err != nil {
			slog.Error("open mailbox", "mailbox", *mailbox, "error", err)
			os.Exit(1)
		}
		runGRPC(sess, *mode, *socketPath, *idleTimeoutStr, *domainsPath, *domainsDataPath, rescanInterval)
		return
	case "pipe":
		// Fall through to pipe protocol below.
	default:
		slog.Error("unknown --mode", "mode", *mode)
		os.Exit(2)
	}

	// ── Pipe mode (backward-compatible default) ──────────────────────────────
	var rspamdClient *rspamd.Client
	if *rspamdURL != "" {
		rspamdClient = rspamd.New(*rspamdURL)
	}

	r := protocol.NewReader(os.Stdin)
	w := protocol.NewWriter(os.Stdout)
	ctx := context.Background()

	var mailboxOpen bool

	cmdCh := make(chan commandResult, 1)
	go readCommands(r, cmdCh)

	var ticker *time.Ticker
	if rescanInterval > 0 {
		ticker = time.NewTicker(rescanInterval)
		defer ticker.Stop()
	}
	tickCh := tickerChan(ticker)

	for {
		select {
		case res := <-cmdCh:
			if res.err != nil {
				if res.err == io.EOF {
					os.Exit(0)
				}
				slog.Error("read command", "err", res.err)
				os.Exit(1)
			}
			exit := handleCommand(ctx, res.cmd, res.data, sess, w, &mailboxOpen,
				rspamdClient, rspamdUser, junkFolder, maxMessageSize)
			if exit {
				return
			}

		case <-tickCh:
			if !mailboxOpen {
				continue
			}
			newMsgs, err := sess.Rescan(ctx)
			if err != nil {
				slog.Warn("periodic rescan failed", "error", err)
				continue
			}
			if len(newMsgs) > 0 {
				lines := formatMessageLines(newMsgs)
				_ = w.WriteNewMail(lines)
			}
		}
	}
}

// runGRPC starts mail-session in daemon or oneshot gRPC mode.
func runGRPC(sess *session.Session, mode, socketPath, idleTimeoutStr, domainsPath, domainsDataPath string, rescanInterval time.Duration) {
	if socketPath == "" {
		slog.Error("--socket is required for " + mode + " mode")
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

// readCommands reads commands from the protocol reader and sends them to ch.
// For APPEND commands, it also reads the body bytes so all I/O on the
// underlying bufio.Reader stays in a single goroutine.
func readCommands(r *protocol.Reader, ch chan<- commandResult) {
	for {
		cmd, err := r.ReadCommand()
		if err != nil {
			ch <- commandResult{err: err}
			return
		}
		var data []byte
		if cmd.Name == protocol.CmdAppend && len(cmd.Args) >= 2 {
			size, serr := strconv.Atoi(cmd.Args[1])
			if serr == nil && size >= 0 {
				data, err = r.ReadBytes(size)
				if err != nil {
					ch <- commandResult{err: fmt.Errorf("APPEND body read: %w", err)}
					return
				}
			}
		}
		ch <- commandResult{cmd: cmd, data: data}
	}
}

// tickerChan returns the ticker's channel, or nil if the ticker is nil.
// A nil channel blocks forever in select, effectively disabling that case.
func tickerChan(t *time.Ticker) <-chan time.Time {
	if t != nil {
		return t.C
	}
	return nil
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

// formatMessageLines formats message info into "uid size flag1 flag2..." lines.
func formatMessageLines(msgs []msgstore.MessageInfo) []string {
	lines := make([]string, 0, len(msgs))
	for _, info := range msgs {
		flags := strings.Join(info.Flags, " ")
		lines = append(lines, fmt.Sprintf("%s %d %s", info.UID, info.Size, flags))
	}
	return lines
}

// handleCommand dispatches a single protocol command. Returns true if the
// process should exit. appendData contains pre-read body bytes for APPEND
// commands (read by the reader goroutine).
func handleCommand(
	ctx context.Context,
	cmd *protocol.Command,
	appendData []byte,
	sess *session.Session,
	w *protocol.Writer,
	mailboxOpen *bool,
	rspamdClient *rspamd.Client,
	rspamdUser *string,
	junkFolder *string,
	maxMessageSize *int64,
) bool {
	switch cmd.Name {

	// ── POP3-path commands ────────────────────────────────────────────────

	case protocol.CmdMailbox:
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("MAILBOX requires an argument")
			return false
		}
		if err := sess.Open(ctx, cmd.Args[0]); err != nil {
			_ = w.WriteErr("cannot open mailbox")
			return false
		}
		*mailboxOpen = true
		_ = w.WriteOK()

	case protocol.CmdList:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		lines := formatMessageLines(sess.List())
		_ = w.WriteOKLines(lines)

	case protocol.CmdStat:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		count, total := sess.Stat()
		_ = w.WriteOKLine(fmt.Sprintf("%d %d", count, total))

	case protocol.CmdGet:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("GET requires a UID argument")
			return false
		}
		uid := cmd.Args[0]
		if _, err := sess.GetUID(uid); err != nil {
			_ = w.WriteErr("message not found")
			return false
		}
		rc, err := sess.Retrieve(ctx, uid)
		if err != nil {
			_ = w.WriteErr("cannot retrieve message")
			return false
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			_ = w.WriteErr("cannot read message")
			return false
		}
		_ = w.WriteData(data)

	case protocol.CmdHeaders:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("HEADERS requires a UID argument")
			return false
		}
		uid := cmd.Args[0]
		nLines := 0
		if len(cmd.Args) >= 2 {
			n, err := strconv.Atoi(cmd.Args[1])
			if err == nil && n > 0 {
				nLines = n
			}
		}
		if _, err := sess.GetUID(uid); err != nil {
			_ = w.WriteErr("message not found")
			return false
		}
		rc, err := sess.Retrieve(ctx, uid)
		if err != nil {
			_ = w.WriteErr("cannot retrieve message")
			return false
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			_ = w.WriteErr("cannot read message")
			return false
		}
		sliced := extractHeaders(data, nLines)
		_ = w.WriteData(sliced)

	case protocol.CmdDelete:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("DELETE requires a UID argument")
			return false
		}
		if err := sess.Delete(cmd.Args[0]); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdUndelete:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("UNDELETE requires a UID argument")
			return false
		}
		if err := sess.Undelete(cmd.Args[0]); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdCommit:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if err := sess.Commit(ctx); err != nil {
			_ = w.WriteErr("commit failed")
			return false
		}
		_ = w.WriteOK()
		os.Exit(0)

	case protocol.CmdQuit:
		_ = w.WriteOK()
		os.Exit(0)

	// ── IMAP-path commands ────────────────────────────────────────────────

	case protocol.CmdSelect:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("SELECT requires a folder argument")
			return false
		}
		msgs, err := sess.Select(ctx, cmd.Args[0])
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLines(formatMessageLines(msgs))

	case protocol.CmdRescan:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		newMsgs, err := sess.Rescan(ctx)
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLines(formatMessageLines(newMsgs))

	case protocol.CmdFolders:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		folders, err := sess.Folders(ctx)
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLines(folders)

	case protocol.CmdUIDValidity:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("UIDVALIDITY requires a folder argument")
			return false
		}
		v, err := sess.UIDValidity(ctx, cmd.Args[0])
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLine(fmt.Sprintf("%d", v))

	case protocol.CmdCreateFolder:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("CREATEFOLDER requires a name argument")
			return false
		}
		if err := sess.CreateFolder(ctx, cmd.Args[0]); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdDeleteFolder:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("DELETEFOLDER requires a name argument")
			return false
		}
		if err := sess.DeleteFolder(ctx, cmd.Args[0]); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdRenameFolder:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 2 {
			_ = w.WriteErr("RENAMEFOLDER requires old and new name arguments")
			return false
		}
		if err := sess.RenameFolder(ctx, cmd.Args[0], cmd.Args[1]); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdSetFlags:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 1 {
			_ = w.WriteErr("SETFLAGS requires a UID argument")
			return false
		}
		uid := cmd.Args[0]
		flags := cmd.Args[1:]
		if err := sess.SetFlags(ctx, uid, flags); err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOK()

	case protocol.CmdExpunge:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		expelled, err := sess.Expunge(ctx)
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLines(expelled)

	case protocol.CmdAppend:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 4 {
			_ = w.WriteErr("APPEND requires: <folder> <size> <flags-or-NONE> <date-rfc3339>")
			return false
		}
		folder := cmd.Args[0]
		if _, err := strconv.Atoi(cmd.Args[1]); err != nil {
			_ = w.WriteErr("APPEND: invalid size")
			return false
		}
		var flags []string
		if cmd.Args[2] != "NONE" {
			flags = strings.Split(cmd.Args[2], ",")
		}
		date, err := time.Parse(time.RFC3339, cmd.Args[3])
		if err != nil {
			_ = w.WriteErr("APPEND: invalid date (want RFC3339)")
			return false
		}
		if appendData == nil {
			_ = w.WriteErr("APPEND: error reading message body")
			return false
		}
		uid, err := sess.AppendMessage(ctx, folder, appendData, flags, date)
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLine(uid)

	case protocol.CmdCopy:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 2 {
			_ = w.WriteErr("COPY requires: <uid> <dest-folder>")
			return false
		}
		newUID, err := sess.CopyMessage(ctx, cmd.Args[0], cmd.Args[1])
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}
		_ = w.WriteOKLine(newUID)

	case protocol.CmdMove:
		if !*mailboxOpen {
			_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
			return false
		}
		if len(cmd.Args) < 3 {
			_ = w.WriteErr("MOVE requires: <uid> <src-folder> <dest-folder>")
			return false
		}
		uid, srcFolder, destFolder := cmd.Args[0], cmd.Args[1], cmd.Args[2]

		rspamdMaxSize := *maxMessageSize
		if rspamdMaxSize <= 0 {
			rspamdMaxSize = 50 * 1024 * 1024
		}
		srcIsJunk := isJunk(srcFolder, *junkFolder)
		destIsJunk := isJunk(destFolder, *junkFolder)
		var msgBytes []byte
		if rspamdClient != nil && (srcIsJunk || destIsJunk) {
			if rc, rerr := sess.RetrieveFrom(ctx, srcFolder, uid); rerr == nil {
				limited, _ := io.ReadAll(io.LimitReader(rc, rspamdMaxSize+1))
				rc.Close()
				if int64(len(limited)) <= rspamdMaxSize {
					msgBytes = limited
				}
			}
		}

		newUID, err := sess.MoveMessage(ctx, uid, srcFolder, destFolder)
		if err != nil {
			_ = w.WriteErr(err.Error())
			return false
		}

		if rspamdClient != nil && len(msgBytes) > 0 {
			go func(spam bool, data []byte) {
				lctx := context.Background()
				var lerr error
				if spam {
					lerr = rspamdClient.LearnSpam(lctx, *rspamdUser, data)
				} else {
					lerr = rspamdClient.LearnHam(lctx, *rspamdUser, data)
				}
				if lerr != nil {
					slog.Warn("rspamd learn failed", "error", lerr)
				}
			}(destIsJunk, msgBytes)
		}

		_ = w.WriteOKLine(newUID)

	default:
		_ = w.WriteErr("unknown command")
	}

	return false
}

// isJunk reports whether folder is the configured Junk folder (case-insensitive).
func isJunk(folder, junkName string) bool {
	return strings.EqualFold(folder, junkName)
}

// extractHeaders returns the header section of a message plus up to nLines of body.
// If nLines is 0, only headers are returned.
// The header/body boundary is the first blank line.
func extractHeaders(data []byte, nLines int) []byte {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	var out strings.Builder
	inBody := false
	bodyCount := 0

	for sc.Scan() {
		line := sc.Text()
		if !inBody {
			out.WriteString(line)
			out.WriteString("\r\n")
			if line == "" {
				inBody = true
			}
		} else {
			if nLines == 0 {
				break
			}
			out.WriteString(line)
			out.WriteString("\r\n")
			bodyCount++
			if bodyCount >= nLines {
				break
			}
		}
	}
	return []byte(out.String())
}
