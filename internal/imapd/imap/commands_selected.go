package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// storeCommand implements the STORE command.
type storeCommand struct{}

func (c *storeCommand) Name() string { return "STORE" }

func (c *storeCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doStore(ctx, tag, args, sess, conn, false)
}

// doStore handles STORE and UID STORE.
func doStore(ctx context.Context, tag, args string, sess *Session, conn *server.Connection, useUID bool) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	if sess.IsReadOnly() {
		return writeNO(w, tag, "Mailbox is read-only")
	}

	// Parse: sequence action flags
	parts := strings.SplitN(args, " ", 3)
	if len(parts) < 3 {
		return writeBAD(w, tag, "STORE requires sequence, action, and flags")
	}

	seqSet, err := ParseSequenceSet(parts[0])
	if err != nil {
		return writeBAD(w, tag, fmt.Sprintf("Invalid sequence set: %s", err.Error()))
	}

	action := strings.ToUpper(parts[1])
	silent := strings.HasSuffix(action, ".SILENT")
	if silent {
		action = strings.TrimSuffix(action, ".SILENT")
	}

	flagsList := ParseStoreFlags(parts[2])

	maxVal := uint32(sess.MessageCount())

	for i := 1; i <= sess.MessageCount(); i++ {
		var match bool
		if useUID {
			uid := sess.MessageUID(i)
			match = seqSet.Contains(uid, sess.UIDNext()-1)
		} else {
			match = seqSet.Contains(uint32(i), maxVal)
		}

		if !match {
			continue
		}

		switch action {
		case "FLAGS":
			sess.SetFlags(i, append([]string(nil), flagsList...))
		case "+FLAGS":
			sess.AddFlags(i, flagsList)
		case "-FLAGS":
			sess.RemoveFlags(i, flagsList)
		default:
			return writeBAD(w, tag, fmt.Sprintf("Unknown store action: %s", action))
		}

		if !silent {
			flags := sess.GetFlags(i)
			resp := fmt.Sprintf("%d FETCH (FLAGS %s", i, formatFlagList(flags))
			if useUID {
				resp += fmt.Sprintf(" UID %d", sess.MessageUID(i))
			}
			resp += ")"
			if err := writeUntagged(w, resp); err != nil {
				return err
			}
		}
	}

	return writeOK(w, tag, "STORE completed")
}

// copyCommand implements the COPY command.
type copyCommand struct{}

func (c *copyCommand) Name() string { return "COPY" }

func (c *copyCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doCopy(ctx, tag, args, sess, conn, false)
}

// doCopy handles COPY and UID COPY.
func doCopy(ctx context.Context, tag, args string, sess *Session, conn *server.Connection, useUID bool) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	// Parse: sequence mailbox
	spaceIdx := strings.IndexByte(args, ' ')
	if spaceIdx < 0 {
		return writeBAD(w, tag, "COPY requires sequence and mailbox")
	}

	seqStr := args[:spaceIdx]
	destMailbox := strings.TrimSpace(args[spaceIdx+1:])
	destMailbox, _ = ParseQuotedOrAtom(destMailbox)

	if destMailbox == "" {
		return writeBAD(w, tag, "Missing destination mailbox")
	}

	seqSet, err := ParseSequenceSet(seqStr)
	if err != nil {
		return writeBAD(w, tag, fmt.Sprintf("Invalid sequence set: %s", err.Error()))
	}

	fs := sess.FolderStore()
	if fs == nil {
		return writeNO(w, tag, "COPY not supported without folder store")
	}

	destFolder := mailboxToFolder(destMailbox)
	srcFolder := mailboxToFolder(sess.SelectedMailbox())
	maxVal := uint32(sess.MessageCount())

	for i := 1; i <= sess.MessageCount(); i++ {
		var match bool
		if useUID {
			uid := sess.MessageUID(i)
			match = seqSet.Contains(uid, sess.UIDNext()-1)
		} else {
			match = seqSet.Contains(uint32(i), maxVal)
		}

		if !match {
			continue
		}

		msg := sess.GetMessage(i)
		if msg == nil {
			continue
		}

		// Retrieve message content
		var reader interface {
			Read([]byte) (int, error)
			Close() error
		}
		if srcFolder == "" {
			reader, err = sess.Store().Retrieve(ctx, sess.Mailbox(), msg.UID)
		} else {
			reader, err = fs.RetrieveFromFolder(ctx, sess.Mailbox(), srcFolder, msg.UID)
		}
		if err != nil {
			sess.Logger().Error("failed to retrieve message for copy", "uid", msg.UID, "error", err.Error())
			continue
		}

		// Deliver to destination
		if destFolder == "" {
			err = fs.DeliverToFolder(ctx, sess.Mailbox(), "", reader)
		} else {
			err = fs.DeliverToFolder(ctx, sess.Mailbox(), destFolder, reader)
		}
		_ = reader.Close()

		if err != nil {
			sess.Logger().Error("failed to copy message", "uid", msg.UID, "dest", destMailbox, "error", err.Error())
			return writeNO(w, tag, "COPY failed")
		}
	}

	return writeOK(w, tag, "COPY completed")
}

// uidCommand implements the UID command prefix.
type uidCommand struct{}

func (c *uidCommand) Name() string { return "UID" }

func (c *uidCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	// Parse sub-command
	spaceIdx := strings.IndexByte(args, ' ')
	var subCmd, subArgs string
	if spaceIdx < 0 {
		subCmd = strings.ToUpper(args)
		subArgs = ""
	} else {
		subCmd = strings.ToUpper(args[:spaceIdx])
		subArgs = args[spaceIdx+1:]
	}

	switch subCmd {
	case "FETCH":
		return doFetch(ctx, tag, subArgs, sess, conn, true)
	case "STORE":
		return doStore(ctx, tag, subArgs, sess, conn, true)
	case "SEARCH":
		return doSearch(ctx, tag, subArgs, sess, conn, true)
	case "COPY":
		return doCopy(ctx, tag, subArgs, sess, conn, true)
	default:
		return writeBAD(w, tag, fmt.Sprintf("Unknown UID sub-command: %s", subCmd))
	}
}
