package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	mserrors "github.com/infodancer/maildancer/internal/mail-session/errors"
	"github.com/infodancer/maildancer/internal/mail-session/protocol"
	"github.com/infodancer/maildancer/internal/mail-session/rspamd"
	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func main() {
	storeType := flag.String("type", "maildir", "message store type")
	basePath := flag.String("basepath", "", "path to store root (required)")
	rspamdURL := flag.String("rspamd", "", "rspamd controller URL (e.g. http://rspamd:11334); empty disables learning")
	junkFolder := flag.String("junk-folder", "Junk", "name of the Junk/Spam folder for rspamd learning")
	flag.Parse()

	if *basePath == "" {
		slog.Error("--basepath is required")
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

	var rspamdClient *rspamd.Client
	if *rspamdURL != "" {
		rspamdClient = rspamd.New(*rspamdURL)
	}

	r := protocol.NewReader(os.Stdin)
	w := protocol.NewWriter(os.Stdout)
	sess := session.New(store)
	ctx := context.Background()

	var mailboxOpen bool

	for {
		cmd, err := r.ReadCommand()
		if err == io.EOF {
			os.Exit(0)
		}
		if err != nil {
			slog.Error("read command", "err", err)
			os.Exit(1)
		}

		switch cmd.Name {

		// ── POP3-path commands ────────────────────────────────────────────────

		case protocol.CmdMailbox:
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("MAILBOX requires an argument")
				continue
			}
			if err := sess.Open(ctx, cmd.Args[0]); err != nil {
				_ = w.WriteErr("cannot open mailbox")
				continue
			}
			mailboxOpen = true
			_ = w.WriteOK()

		case protocol.CmdList:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			infos := sess.List()
			lines := make([]string, 0, len(infos))
			for _, info := range infos {
				flags := strings.Join(info.Flags, " ")
				lines = append(lines, fmt.Sprintf("%s %d %s", info.UID, info.Size, flags))
			}
			_ = w.WriteOKLines(lines)

		case protocol.CmdStat:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			count, total := sess.Stat()
			_ = w.WriteOKLine(fmt.Sprintf("%d %d", count, total))

		case protocol.CmdGet:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("GET requires a UID argument")
				continue
			}
			uid := cmd.Args[0]
			if _, err := sess.GetUID(uid); err != nil {
				_ = w.WriteErr("message not found")
				continue
			}
			rc, err := sess.Retrieve(ctx, uid)
			if err != nil {
				_ = w.WriteErr("cannot retrieve message")
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				_ = w.WriteErr("cannot read message")
				continue
			}
			_ = w.WriteData(data)

		case protocol.CmdHeaders:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("HEADERS requires a UID argument")
				continue
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
				continue
			}
			rc, err := sess.Retrieve(ctx, uid)
			if err != nil {
				_ = w.WriteErr("cannot retrieve message")
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				_ = w.WriteErr("cannot read message")
				continue
			}
			sliced := extractHeaders(data, nLines)
			_ = w.WriteData(sliced)

		case protocol.CmdDelete:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("DELETE requires a UID argument")
				continue
			}
			if err := sess.Delete(cmd.Args[0]); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdUndelete:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("UNDELETE requires a UID argument")
				continue
			}
			if err := sess.Undelete(cmd.Args[0]); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdCommit:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if err := sess.Commit(ctx); err != nil {
				_ = w.WriteErr("commit failed")
				continue
			}
			_ = w.WriteOK()
			os.Exit(0)

		case protocol.CmdQuit:
			_ = w.WriteOK()
			os.Exit(0)

		// ── IMAP-path commands ────────────────────────────────────────────────

		case protocol.CmdSelect:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("SELECT requires a folder argument")
				continue
			}
			msgs, err := sess.Select(ctx, cmd.Args[0])
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			lines := make([]string, 0, len(msgs))
			for _, info := range msgs {
				flags := strings.Join(info.Flags, " ")
				lines = append(lines, fmt.Sprintf("%s %d %s", info.UID, info.Size, flags))
			}
			_ = w.WriteOKLines(lines)

		case protocol.CmdFolders:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			folders, err := sess.Folders(ctx)
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOKLines(folders)

		case protocol.CmdUIDValidity:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("UIDVALIDITY requires a folder argument")
				continue
			}
			v, err := sess.UIDValidity(ctx, cmd.Args[0])
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOKLine(fmt.Sprintf("%d", v))

		case protocol.CmdCreateFolder:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("CREATEFOLDER requires a name argument")
				continue
			}
			if err := sess.CreateFolder(ctx, cmd.Args[0]); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdDeleteFolder:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("DELETEFOLDER requires a name argument")
				continue
			}
			if err := sess.DeleteFolder(ctx, cmd.Args[0]); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdRenameFolder:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 2 {
				_ = w.WriteErr("RENAMEFOLDER requires old and new name arguments")
				continue
			}
			if err := sess.RenameFolder(ctx, cmd.Args[0], cmd.Args[1]); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdSetFlags:
			// SETFLAGS <uid> [<flag1> <flag2> ...]
			// Flags after the UID become the complete new flag set.
			// No flags after UID means clear all flags.
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 1 {
				_ = w.WriteErr("SETFLAGS requires a UID argument")
				continue
			}
			uid := cmd.Args[0]
			flags := cmd.Args[1:] // may be empty (clears all flags)
			if err := sess.SetFlags(ctx, uid, flags); err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOK()

		case protocol.CmdExpunge:
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			expelled, err := sess.Expunge(ctx)
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOKLines(expelled)

		case protocol.CmdAppend:
			// APPEND <folder> <size> <flags-space-sep-or-NONE> <date-rfc3339>
			// Immediately followed by <size> raw bytes (no line terminator).
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 4 {
				_ = w.WriteErr("APPEND requires: <folder> <size> <flags-or-NONE> <date-rfc3339>")
				continue
			}
			folder := cmd.Args[0]
			size, err := strconv.Atoi(cmd.Args[1])
			if err != nil || size < 0 {
				_ = w.WriteErr("APPEND: invalid size")
				continue
			}
			var flags []string
			if cmd.Args[2] != "NONE" {
				flags = strings.Split(cmd.Args[2], ",")
			}
			date, err := time.Parse(time.RFC3339, cmd.Args[3])
			if err != nil {
				_ = w.WriteErr("APPEND: invalid date (want RFC3339)")
				continue
			}
			data, err := r.ReadBytes(size)
			if err != nil {
				_ = w.WriteErr("APPEND: error reading message body")
				continue
			}
			uid, err := sess.AppendMessage(ctx, folder, data, flags, date)
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOKLine(uid)

		case protocol.CmdCopy:
			// COPY <uid> <dest-folder>
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 2 {
				_ = w.WriteErr("COPY requires: <uid> <dest-folder>")
				continue
			}
			newUID, err := sess.CopyMessage(ctx, cmd.Args[0], cmd.Args[1])
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}
			_ = w.WriteOKLine(newUID)

		case protocol.CmdMove:
			// MOVE <uid> <src-folder> <dest-folder>
			if !mailboxOpen {
				_ = w.WriteErr(mserrors.ErrMailboxNotOpen.Error())
				continue
			}
			if len(cmd.Args) < 3 {
				_ = w.WriteErr("MOVE requires: <uid> <src-folder> <dest-folder>")
				continue
			}
			uid, srcFolder, destFolder := cmd.Args[0], cmd.Args[1], cmd.Args[2]

			// Retrieve message bytes for rspamd learning before the move.
			var msgBytes []byte
			if rspamdClient != nil && (isJunk(srcFolder, *junkFolder) || isJunk(destFolder, *junkFolder)) {
				if rc, rerr := sess.RetrieveFrom(ctx, srcFolder, uid); rerr == nil {
					msgBytes, _ = io.ReadAll(rc)
					rc.Close()
				}
			}

			newUID, err := sess.MoveMessage(ctx, uid, srcFolder, destFolder)
			if err != nil {
				_ = w.WriteErr(err.Error())
				continue
			}

			// Fire-and-forget rspamd learning — never blocks or fails the MOVE.
			if rspamdClient != nil && len(msgBytes) > 0 {
				learnSpam := isJunk(destFolder, *junkFolder)
				user := sess.Mailbox()
				go func(spam bool, data []byte) {
					lctx := context.Background()
					var lerr error
					if spam {
						lerr = rspamdClient.LearnSpam(lctx, user, data)
					} else {
						lerr = rspamdClient.LearnHam(lctx, user, data)
					}
					if lerr != nil {
						slog.Warn("rspamd learn failed", "error", lerr)
					}
				}(learnSpam, msgBytes)
			}

			_ = w.WriteOKLine(newUID)

		default:
			_ = w.WriteErr("unknown command")
		}
	}
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
