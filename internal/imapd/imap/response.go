package imap

import (
	"fmt"
	"strings"
)

// writeTagged writes a tagged response: "<tag> OK/NO/BAD <text>\r\n".
func writeTagged(w writer, tag, status, text string) error {
	line := fmt.Sprintf("%s %s %s\r\n", tag, status, text)
	_, err := w.WriteString(line)
	return err
}

// writeOK writes a tagged OK response.
func writeOK(w writer, tag, text string) error {
	return writeTagged(w, tag, "OK", text)
}

// writeNO writes a tagged NO response.
func writeNO(w writer, tag, text string) error {
	return writeTagged(w, tag, "NO", text)
}

// writeBAD writes a tagged BAD response.
func writeBAD(w writer, tag, text string) error {
	return writeTagged(w, tag, "BAD", text)
}

// writeUntagged writes an untagged response: "* <data>\r\n".
func writeUntagged(w writer, data string) error {
	line := fmt.Sprintf("* %s\r\n", data)
	_, err := w.WriteString(line)
	return err
}

// writeContinuation writes a continuation response: "+ <text>\r\n".
func writeContinuation(w writer, text string) error {
	line := fmt.Sprintf("+ %s\r\n", text)
	_, err := w.WriteString(line)
	return err
}

// formatFlagList formats a slice of flags as an IMAP flag list: "(\Seen \Flagged)".
func formatFlagList(flags []string) string {
	return "(" + strings.Join(flags, " ") + ")"
}

// quoteString returns an IMAP quoted string.
func quoteString(s string) string {
	// Replace backslash and double-quote with escaped versions.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// nilOrQuote returns NIL for empty strings, quoted otherwise.
func nilOrQuote(s string) string {
	if s == "" {
		return "NIL"
	}
	return quoteString(s)
}

// writer is a minimal interface for writing strings (satisfied by bufio.Writer).
type writer interface {
	WriteString(s string) (int, error)
}
