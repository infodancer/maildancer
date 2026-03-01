package protocol

import (
	"bufio"
	"io"
	"strings"
)

// Reader wraps a bufio.Reader and parses session pipe commands.
type Reader struct {
	r *bufio.Reader
}

// NewReader returns a Reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

// ReadCommand reads one CRLF- or LF-terminated line and returns the parsed Command.
// Returns io.EOF when the underlying reader is exhausted.
func (r *Reader) ReadCommand() (*Command, error) {
	line, err := r.r.ReadString('\n')
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			// partial line with no terminator — treat as a command anyway
		} else {
			return nil, err
		}
	}

	// Strip trailing CRLF or LF.
	line = strings.TrimRight(line, "\r\n")

	fields := strings.Fields(line)
	if len(fields) == 0 {
		// Empty line — recurse to read next command.
		return r.ReadCommand()
	}

	cmd := &Command{
		Name: strings.ToUpper(fields[0]),
		Args: fields[1:],
	}
	return cmd, nil
}

// ReadBytes reads exactly n bytes from the underlying reader.
// Used to consume the raw message body following an APPEND command line.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r.r, buf)
	return buf, err
}
