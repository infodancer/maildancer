package imap

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// selectCommand implements the SELECT command.
type selectCommand struct{}

func (c *selectCommand) Name() string { return "SELECT" }

func (c *selectCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doSelect(ctx, tag, args, sess, conn, false)
}

// examineCommand implements the EXAMINE command.
type examineCommand struct{}

func (c *examineCommand) Name() string { return "EXAMINE" }

func (c *examineCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doSelect(ctx, tag, args, sess, conn, true)
}

// doSelect handles both SELECT and EXAMINE.
func doSelect(ctx context.Context, tag, args string, sess *Session, conn *server.Connection, readOnly bool) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	mailbox, _ := ParseQuotedOrAtom(args)
	if mailbox == "" {
		return writeBAD(w, tag, "Missing mailbox name")
	}

	// If already selected, deselect first
	if sess.State() == StateSelected {
		sess.DeselectMailbox()
	}

	if err := sess.SelectMailbox(ctx, mailbox, readOnly); err != nil {
		return writeNO(w, tag, fmt.Sprintf("Failed to select mailbox: %s", err.Error()))
	}

	sess.Collector().FolderSelected(sess.UserDomain())

	// Send mailbox information
	if err := writeUntagged(w, fmt.Sprintf("%d EXISTS", sess.MessageCount())); err != nil {
		return err
	}
	if err := writeUntagged(w, fmt.Sprintf("%d RECENT", sess.RecentCount())); err != nil {
		return err
	}
	if err := writeUntagged(w, "FLAGS "+formatFlagList(SystemFlags)); err != nil {
		return err
	}

	if unseen := sess.FirstUnseen(); unseen > 0 {
		if err := writeUntagged(w, fmt.Sprintf("OK [UNSEEN %d] First unseen message", unseen)); err != nil {
			return err
		}
	}

	if err := writeUntagged(w, fmt.Sprintf("OK [UIDVALIDITY %d] UIDs valid", sess.UIDValidity())); err != nil {
		return err
	}
	if err := writeUntagged(w, fmt.Sprintf("OK [UIDNEXT %d] Predicted next UID", sess.UIDNext())); err != nil {
		return err
	}
	if err := writeUntagged(w, "OK [PERMANENTFLAGS "+formatFlagList(append(PermanentFlags, `\*`))+"] Permanent flags"); err != nil {
		return err
	}

	cmdName := "SELECT"
	access := "[READ-WRITE]"
	if readOnly {
		cmdName = "EXAMINE"
		access = "[READ-ONLY]"
	}

	return writeOK(w, tag, fmt.Sprintf("%s %s completed", access, cmdName))
}

// createCommand implements the CREATE command.
type createCommand struct{}

func (c *createCommand) Name() string { return "CREATE" }

func (c *createCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	mailbox, _ := ParseQuotedOrAtom(args)
	if mailbox == "" {
		return writeBAD(w, tag, "Missing mailbox name")
	}

	if strings.EqualFold(mailbox, "INBOX") {
		return writeNO(w, tag, "Cannot create INBOX")
	}

	fs := sess.FolderStore()
	if fs == nil {
		return writeNO(w, tag, "Folder operations not supported")
	}

	if err := fs.CreateFolder(ctx, sess.Mailbox(), mailbox); err != nil {
		return writeNO(w, tag, fmt.Sprintf("CREATE failed: %s", err.Error()))
	}

	return writeOK(w, tag, "CREATE completed")
}

// deleteCommand implements the DELETE command.
type deleteCommand struct{}

func (c *deleteCommand) Name() string { return "DELETE" }

func (c *deleteCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	mailbox, _ := ParseQuotedOrAtom(args)
	if mailbox == "" {
		return writeBAD(w, tag, "Missing mailbox name")
	}

	if strings.EqualFold(mailbox, "INBOX") {
		return writeNO(w, tag, "Cannot delete INBOX")
	}

	fs := sess.FolderStore()
	if fs == nil {
		return writeNO(w, tag, "Folder operations not supported")
	}

	if err := fs.DeleteFolder(ctx, sess.Mailbox(), mailbox); err != nil {
		return writeNO(w, tag, fmt.Sprintf("DELETE failed: %s", err.Error()))
	}

	return writeOK(w, tag, "DELETE completed")
}

// renameCommand implements the RENAME command.
type renameCommand struct{}

func (c *renameCommand) Name() string { return "RENAME" }

func (c *renameCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return writeNO(conn.Writer(), tag, "RENAME not supported")
}

// subscribeCommand implements the SUBSCRIBE command.
type subscribeCommand struct{}

func (c *subscribeCommand) Name() string { return "SUBSCRIBE" }

func (c *subscribeCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(conn.Writer(), tag, "Command requires authenticated state")
	}
	// Accept but no-op
	return writeOK(conn.Writer(), tag, "SUBSCRIBE completed")
}

// unsubscribeCommand implements the UNSUBSCRIBE command.
type unsubscribeCommand struct{}

func (c *unsubscribeCommand) Name() string { return "UNSUBSCRIBE" }

func (c *unsubscribeCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(conn.Writer(), tag, "Command requires authenticated state")
	}
	// Accept but no-op
	return writeOK(conn.Writer(), tag, "UNSUBSCRIBE completed")
}

// listCommand implements the LIST command.
type listCommand struct{}

func (c *listCommand) Name() string { return "LIST" }

func (c *listCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	// Parse reference and mailbox pattern
	ref, rest := ParseQuotedOrAtom(args)
	pattern, _ := ParseQuotedOrAtom(rest)

	// Special case: LIST "" "" returns hierarchy delimiter
	if ref == "" && pattern == "" {
		if err := writeUntagged(w, `LIST (\Noselect) "/" ""`); err != nil {
			return err
		}
		return writeOK(w, tag, "LIST completed")
	}

	// Always include INBOX
	if matchPattern(pattern, "INBOX") {
		if err := writeUntagged(w, `LIST () "/" "INBOX"`); err != nil {
			return err
		}
	}

	// List folders from store
	fs := sess.FolderStore()
	if fs != nil {
		folders, err := fs.ListFolders(ctx, sess.Mailbox())
		if err != nil {
			sess.Logger().Error("failed to list folders", "error", err.Error())
		} else {
			for _, folder := range folders {
				if matchPattern(pattern, folder) {
					if err := writeUntagged(w, fmt.Sprintf(`LIST () "/" %s`, quoteString(folder))); err != nil {
						return err
					}
				}
			}
		}
	}

	return writeOK(w, tag, "LIST completed")
}

// lsubCommand implements the LSUB command.
type lsubCommand struct{}

func (c *lsubCommand) Name() string { return "LSUB" }

func (c *lsubCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	// Parse reference and mailbox pattern
	ref, rest := ParseQuotedOrAtom(args)
	pattern, _ := ParseQuotedOrAtom(rest)

	// Special case: LSUB "" "" returns hierarchy delimiter
	if ref == "" && pattern == "" {
		if err := writeUntagged(w, `LSUB (\Noselect) "/" ""`); err != nil {
			return err
		}
		return writeOK(w, tag, "LSUB completed")
	}

	// Same as LIST for now (no subscription tracking)
	if matchPattern(pattern, "INBOX") {
		if err := writeUntagged(w, `LSUB () "/" "INBOX"`); err != nil {
			return err
		}
	}

	fs := sess.FolderStore()
	if fs != nil {
		folders, err := fs.ListFolders(ctx, sess.Mailbox())
		if err != nil {
			sess.Logger().Error("failed to list folders", "error", err.Error())
		} else {
			for _, folder := range folders {
				if matchPattern(pattern, folder) {
					if err := writeUntagged(w, fmt.Sprintf(`LSUB () "/" %s`, quoteString(folder))); err != nil {
						return err
					}
				}
			}
		}
	}

	return writeOK(w, tag, "LSUB completed")
}

// statusCommand implements the STATUS command.
type statusCommand struct{}

func (c *statusCommand) Name() string { return "STATUS" }

func (c *statusCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	// Parse mailbox name
	mailbox, rest := ParseQuotedOrAtom(args)
	if mailbox == "" {
		return writeBAD(w, tag, "Missing mailbox name")
	}

	// Parse status items
	items, err := ParseParenList(strings.TrimSpace(rest))
	if err != nil {
		return writeBAD(w, tag, "Invalid status data items")
	}

	// Get mailbox stats
	folder := mailboxToFolder(mailbox)
	var msgCount int
	var totalBytes int64

	if folder == "" {
		msgCount, totalBytes, err = sess.Store().Stat(ctx, sess.Mailbox())
	} else if sess.FolderStore() != nil {
		msgCount, totalBytes, err = sess.FolderStore().StatFolder(ctx, sess.Mailbox(), folder)
	} else {
		return writeNO(w, tag, "Folder not found")
	}

	if err != nil {
		return writeNO(w, tag, fmt.Sprintf("STATUS failed: %s", err.Error()))
	}

	_ = totalBytes // Not directly used in STATUS items

	// Build response
	var statusItems []string
	for _, item := range items {
		switch strings.ToUpper(item) {
		case "MESSAGES":
			statusItems = append(statusItems, fmt.Sprintf("MESSAGES %d", msgCount))
		case "RECENT":
			statusItems = append(statusItems, "RECENT 0")
		case "UIDNEXT":
			statusItems = append(statusItems, fmt.Sprintf("UIDNEXT %d", msgCount+1))
		case "UIDVALIDITY":
			statusItems = append(statusItems, fmt.Sprintf("UIDVALIDITY %d", sess.UIDValidity()))
		case "UNSEEN":
			statusItems = append(statusItems, fmt.Sprintf("UNSEEN %d", msgCount)) // conservative estimate
		}
	}

	resp := fmt.Sprintf("STATUS %s (%s)", quoteString(mailbox), strings.Join(statusItems, " "))
	if err := writeUntagged(w, resp); err != nil {
		return err
	}

	return writeOK(w, tag, "STATUS completed")
}

// appendCommand implements the APPEND command.
type appendCommand struct{}

func (c *appendCommand) Name() string { return "APPEND" }

func (c *appendCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateAuthenticated && sess.State() != StateSelected {
		return writeBAD(w, tag, "Command requires authenticated state")
	}

	// Parse: mailbox [(flags)] [date] {size}
	mailbox, rest := ParseQuotedOrAtom(args)
	if mailbox == "" {
		return writeBAD(w, tag, "Missing mailbox name")
	}

	// Skip optional flags and date for now -- look for the literal
	rest = strings.TrimSpace(rest)

	// Parse optional flags
	if strings.HasPrefix(rest, "(") {
		closeIdx := strings.IndexByte(rest, ')')
		if closeIdx < 0 {
			return writeBAD(w, tag, "Unmatched parenthesis in flags")
		}
		// flags = rest[1:closeIdx]  -- we accept but don't use flags on APPEND
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}

	// Parse optional date-time
	if strings.HasPrefix(rest, `"`) {
		_, rest = ParseQuotedOrAtom(rest)
		rest = strings.TrimSpace(rest)
	}

	// Parse literal size {N} or {N+}
	if !strings.HasPrefix(rest, "{") || !strings.HasSuffix(rest, "}") {
		return writeBAD(w, tag, "Missing message literal")
	}

	sizeStr := rest[1 : len(rest)-1]
	literalPlus := strings.HasSuffix(sizeStr, "+")
	if literalPlus {
		sizeStr = sizeStr[:len(sizeStr)-1]
	}

	var size int
	if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil || size < 0 {
		return writeBAD(w, tag, "Invalid literal size")
	}

	// Send continuation unless LITERAL+
	if !literalPlus {
		if err := writeContinuation(w, "Ready for literal data"); err != nil {
			return err
		}
		if err := flushConn(conn); err != nil {
			return err
		}
	}

	// Read literal data
	data := make([]byte, size)
	if _, err := io.ReadFull(conn.Reader(), data); err != nil {
		return writeNO(w, tag, "Failed to read message data")
	}

	// Read trailing CRLF
	_, _ = conn.Reader().ReadString('\n')

	// Deliver to folder
	folder := mailboxToFolder(mailbox)
	reader := strings.NewReader(string(data))

	if folder == "" {
		// Deliver to INBOX -- use DeliveryAgent if available through the store
		// For now, just report success. Full delivery requires the DeliveryAgent interface.
		// If the store implements FolderStore, use DeliverToFolder with empty folder.
		fs := sess.FolderStore()
		if fs != nil {
			if err := fs.DeliverToFolder(ctx, sess.Mailbox(), "", reader); err != nil {
				return writeNO(w, tag, fmt.Sprintf("APPEND failed: %s", err.Error()))
			}
		} else {
			return writeNO(w, tag, "APPEND not supported for INBOX without folder store")
		}
	} else {
		fs := sess.FolderStore()
		if fs == nil {
			return writeNO(w, tag, "Folder operations not supported")
		}
		if err := fs.DeliverToFolder(ctx, sess.Mailbox(), folder, reader); err != nil {
			return writeNO(w, tag, fmt.Sprintf("APPEND failed: %s", err.Error()))
		}
	}

	sess.Collector().MessageStored(sess.UserDomain())
	return writeOK(w, tag, "APPEND completed")
}

// closeCommand implements the CLOSE command.
type closeCommand struct{}

func (c *closeCommand) Name() string { return "CLOSE" }

func (c *closeCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	// Expunge deleted messages silently (no untagged EXPUNGE responses)
	if !sess.IsReadOnly() {
		if _, err := sess.ExpungeDeleted(ctx); err != nil {
			sess.Logger().Error("close expunge failed", "error", err.Error())
		}
	}

	sess.DeselectMailbox()
	return writeOK(w, tag, "CLOSE completed")
}

// expungeCommand implements the EXPUNGE command.
type expungeCommand struct{}

func (c *expungeCommand) Name() string { return "EXPUNGE" }

func (c *expungeCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	if sess.IsReadOnly() {
		return writeNO(w, tag, "Mailbox is read-only")
	}

	expunged, err := sess.ExpungeDeleted(ctx)
	if err != nil {
		return writeNO(w, tag, fmt.Sprintf("EXPUNGE failed: %s", err.Error()))
	}

	// Send untagged EXPUNGE for each removed message
	for _, seqNum := range expunged {
		if err := writeUntagged(w, fmt.Sprintf("%d EXPUNGE", seqNum)); err != nil {
			return err
		}
		sess.Collector().MessageExpunged(sess.UserDomain())
	}

	return writeOK(w, tag, "EXPUNGE completed")
}

// matchPattern matches an IMAP mailbox pattern against a name.
// Supports * (matches anything) and % (matches anything except hierarchy delimiter).
func matchPattern(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == "%" {
		return !strings.Contains(name, "/")
	}

	// Simple wildcard matching
	return matchWildcard(strings.ToUpper(pattern), strings.ToUpper(name))
}

// matchWildcard performs simple wildcard matching with * and %.
func matchWildcard(pattern, name string) bool {
	if pattern == "" {
		return name == ""
	}

	if pattern[0] == '*' {
		// * matches everything
		for i := 0; i <= len(name); i++ {
			if matchWildcard(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	}

	if pattern[0] == '%' {
		// % matches everything except /
		for i := 0; i <= len(name); i++ {
			if i > 0 && name[i-1] == '/' {
				break
			}
			if matchWildcard(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	}

	if name == "" {
		return false
	}

	if pattern[0] == name[0] {
		return matchWildcard(pattern[1:], name[1:])
	}

	return false
}

// formatInternalDate formats a time as an IMAP INTERNALDATE string.
func formatInternalDate(t time.Time) string {
	return `"` + t.Format("02-Jan-2006 15:04:05 -0700") + `"`
}
