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

	mserrors "github.com/infodancer/maildancer/internal/mail-session/errors"
	"github.com/infodancer/maildancer/internal/mail-session/protocol"
	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func main() {
	storeType := flag.String("type", "maildir", "message store type")
	basePath := flag.String("basepath", "", "path to store root (required)")
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
			rc, err := store.Retrieve(ctx, sess.Mailbox(), uid)
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
			rc, err := store.Retrieve(ctx, sess.Mailbox(), uid)
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

		default:
			_ = w.WriteErr("unknown command")
		}
	}
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
