package pop3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// statCommand implements the STAT command (RFC 1939).
// Returns the number of messages and total size in octets.
type statCommand struct{}

func (s *statCommand) Name() string {
	return "STAT"
}

func (s *statCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// STAT is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// STAT takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "STAT command takes no arguments"}, nil
	}

	count := sess.MessageCount()
	size := sess.TotalSize()

	return Response{OK: true, Message: fmt.Sprintf("%d %d", count, size)}, nil
}

// listCommand implements the LIST command (RFC 1939).
// Without arguments, lists all messages. With argument, lists one message.
type listCommand struct{}

func (l *listCommand) Name() string {
	return "LIST"
}

func (l *listCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// LIST is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// LIST with no arguments - list all messages
	if len(args) == 0 {
		messages := sess.AllMessages()
		lines := make([]string, len(messages))
		for i, m := range messages {
			lines[i] = fmt.Sprintf("%d %d", m.MsgNum, m.Info.Size)
		}
		return Response{
			OK:      true,
			Message: fmt.Sprintf("%d messages (%d octets)", sess.MessageCount(), sess.TotalSize()),
			Lines:   lines,
		}, nil
	}

	// LIST with one argument - list specific message
	if len(args) != 1 {
		return Response{OK: false, Message: "LIST command takes at most one argument"}, nil
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil {
		return Response{OK: false, Message: "Invalid message number"}, nil
	}

	msg, err := sess.GetMessage(msgNum)
	if err != nil {
		if errors.Is(err, ErrNoSuchMessage) || errors.Is(err, ErrMessageDeleted) {
			return Response{OK: false, Message: "No such message"}, nil
		}
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}

	return Response{OK: true, Message: fmt.Sprintf("%d %d", msgNum, msg.Size)}, nil
}

// retrCommand implements the RETR command (RFC 1939).
// Retrieves and sends the full message content.
type retrCommand struct{}

func (r *retrCommand) Name() string {
	return "RETR"
}

func (r *retrCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// RETR is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// RETR requires exactly one argument
	if len(args) != 1 {
		return Response{OK: false, Message: "RETR command requires message number"}, nil
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil {
		return Response{OK: false, Message: "Invalid message number"}, nil
	}

	msg, err := sess.GetMessage(msgNum)
	if err != nil {
		if errors.Is(err, ErrNoSuchMessage) || errors.Is(err, ErrMessageDeleted) {
			return Response{OK: false, Message: "No such message"}, nil
		}
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}

	store := sess.Store()
	if store == nil {
		return Response{OK: false, Message: "Message store not available"}, nil
	}

	// Retrieve message content
	reader, err := store.Retrieve(ctx, sess.Mailbox(), msg.UID)
	if err != nil {
		conn.Logger().Error("failed to retrieve message content",
			"msgNum", msgNum,
			"uid", msg.UID,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}
	defer func() {
		_ = reader.Close()
	}()

	// Read all content and convert to lines
	content, err := io.ReadAll(reader)
	if err != nil {
		conn.Logger().Error("failed to read message content",
			"msgNum", msgNum,
			"uid", msg.UID,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Failed to read message"}, nil
	}

	// Split content into lines (preserving original line endings as much as possible)
	lines := splitMessageLines(string(content))

	return Response{
		OK:      true,
		Message: fmt.Sprintf("%d octets", msg.Size),
		Lines:   lines,
	}, nil
}

// deleCommand implements the DELE command (RFC 1939).
// Marks a message for deletion.
type deleCommand struct{}

func (d *deleCommand) Name() string {
	return "DELE"
}

func (d *deleCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// DELE is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// DELE requires exactly one argument
	if len(args) != 1 {
		return Response{OK: false, Message: "DELE command requires message number"}, nil
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil {
		return Response{OK: false, Message: "Invalid message number"}, nil
	}

	err = sess.MarkDeleted(msgNum)
	if err != nil {
		if errors.Is(err, ErrNoSuchMessage) {
			return Response{OK: false, Message: "No such message"}, nil
		}
		if errors.Is(err, ErrMessageDeleted) {
			return Response{OK: false, Message: "Message already deleted"}, nil
		}
		return Response{OK: false, Message: "Failed to delete message"}, nil
	}

	return Response{OK: true, Message: fmt.Sprintf("message %d deleted", msgNum)}, nil
}

// rsetCommand implements the RSET command (RFC 1939).
// Unmarks all messages marked for deletion.
type rsetCommand struct{}

func (r *rsetCommand) Name() string {
	return "RSET"
}

func (r *rsetCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// RSET is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// RSET takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "RSET command takes no arguments"}, nil
	}

	sess.ResetDeletions()

	return Response{OK: true, Message: fmt.Sprintf("maildrop has %d messages", sess.MessageCount())}, nil
}

// noopCommand implements the NOOP command (RFC 1939).
// Does nothing, returns success.
type noopCommand struct{}

func (n *noopCommand) Name() string {
	return "NOOP"
}

func (n *noopCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// NOOP takes no arguments
	if len(args) > 0 {
		return Response{OK: false, Message: "NOOP command takes no arguments"}, nil
	}

	return Response{OK: true, Message: ""}, nil
}

// uidlCommand implements the UIDL command (RFC 1939 extension).
// Returns unique identifiers for messages.
type uidlCommand struct{}

func (u *uidlCommand) Name() string {
	return "UIDL"
}

func (u *uidlCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// UIDL is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// UIDL with no arguments - list all messages
	if len(args) == 0 {
		messages := sess.AllMessages()
		lines := make([]string, len(messages))
		for i, m := range messages {
			lines[i] = fmt.Sprintf("%d %s", m.MsgNum, m.Info.UID)
		}
		return Response{
			OK:      true,
			Message: "",
			Lines:   lines,
		}, nil
	}

	// UIDL with one argument - get specific message UID
	if len(args) != 1 {
		return Response{OK: false, Message: "UIDL command takes at most one argument"}, nil
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil {
		return Response{OK: false, Message: "Invalid message number"}, nil
	}

	msg, err := sess.GetMessage(msgNum)
	if err != nil {
		if errors.Is(err, ErrNoSuchMessage) || errors.Is(err, ErrMessageDeleted) {
			return Response{OK: false, Message: "No such message"}, nil
		}
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}

	return Response{OK: true, Message: fmt.Sprintf("%d %s", msgNum, msg.UID)}, nil
}

// topCommand implements the TOP command (RFC 2449).
// Returns headers and n lines of the message body.
type topCommand struct{}

func (t *topCommand) Name() string {
	return "TOP"
}

func (t *topCommand) Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error) {
	// TOP is only valid in TRANSACTION state
	if sess.State() != StateTransaction {
		return Response{OK: false, Message: "Command not valid in this state"}, nil
	}

	// TOP requires exactly two arguments: msgnum and n
	if len(args) != 2 {
		return Response{OK: false, Message: "TOP command requires message number and line count"}, nil
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil {
		return Response{OK: false, Message: "Invalid message number"}, nil
	}

	lineCount, err := strconv.Atoi(args[1])
	if err != nil || lineCount < 0 {
		return Response{OK: false, Message: "Invalid line count"}, nil
	}

	msg, err := sess.GetMessage(msgNum)
	if err != nil {
		if errors.Is(err, ErrNoSuchMessage) || errors.Is(err, ErrMessageDeleted) {
			return Response{OK: false, Message: "No such message"}, nil
		}
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}

	store := sess.Store()
	if store == nil {
		return Response{OK: false, Message: "Message store not available"}, nil
	}

	reader, err := store.Retrieve(ctx, sess.Mailbox(), msg.UID)
	if err != nil {
		conn.Logger().Error("failed to retrieve message content",
			"msgNum", msgNum,
			"uid", msg.UID,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Failed to retrieve message"}, nil
	}
	lines, err := extractTopLines(reader, lineCount)
	_ = reader.Close()
	if err != nil {
		conn.Logger().Error("failed to parse message",
			"msgNum", msgNum,
			"uid", msg.UID,
			"error", err.Error(),
		)
		return Response{OK: false, Message: "Failed to read message"}, nil
	}

	return Response{
		OK:      true,
		Message: "",
		Lines:   lines,
	}, nil
}

// splitMessageLines splits message content into lines for POP3 response.
// Handles both LF and CRLF line endings.
func splitMessageLines(content string) []string {
	// Normalize line endings
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Split on newlines
	rawLines := strings.Split(content, "\n")

	// Remove trailing empty line if present (from trailing newline)
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}

	return rawLines
}

// extractTopLines extracts headers and n lines of body from a message.
func extractTopLines(reader io.Reader, bodyLines int) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	var lines []string
	inBody := false
	bodyCount := 0

	for scanner.Scan() {
		line := scanner.Text()

		if !inBody {
			// We're in headers
			lines = append(lines, line)
			if line == "" {
				// Empty line signals end of headers
				inBody = true
			}
		} else {
			// We're in body
			if bodyCount >= bodyLines {
				break
			}
			lines = append(lines, line)
			bodyCount++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// RegisterTransactionCommands registers all transaction-related commands.
func RegisterTransactionCommands() {
	RegisterCommand(&statCommand{})
	RegisterCommand(&listCommand{})
	RegisterCommand(&retrCommand{})
	RegisterCommand(&deleCommand{})
	RegisterCommand(&rsetCommand{})
	RegisterCommand(&noopCommand{})
	RegisterCommand(&uidlCommand{})
	RegisterCommand(&topCommand{})
}
