package pop3

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// authSignal carries the parsed content of an authentication signal written by
// the protocol-handler to the auth pipe (fd 4) after the user has
// authenticated successfully.
//
// Wire format (CRLF-terminated lines):
//
//	AUTH <version>\r\n
//	USER:<localpart@domain>\r\n
//	END\r\n
type authSignal struct {
	Version  int
	Username string // localpart@domain as authenticated
}

// readAuthSignal reads and parses one auth signal from r.
// Returns an error if the format is invalid or if r reaches EOF before
// a complete signal is received.
func readAuthSignal(r io.Reader) (*authSignal, error) {
	s := bufio.NewScanner(r)

	// Line 1: AUTH <version>
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return nil, fmt.Errorf("read AUTH line: %w", err)
		}
		return nil, fmt.Errorf("read AUTH line: unexpected EOF")
	}
	line := strings.TrimRight(s.Text(), "\r")
	versionStr, ok := strings.CutPrefix(line, "AUTH ")
	if !ok {
		return nil, fmt.Errorf("expected AUTH line, got %q", line)
	}
	version, err := strconv.Atoi(strings.TrimSpace(versionStr))
	if err != nil || version != 1 {
		return nil, fmt.Errorf("unsupported auth signal version in %q", line)
	}

	// Line 2: USER:<username>
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return nil, fmt.Errorf("read USER line: %w", err)
		}
		return nil, fmt.Errorf("read USER line: unexpected EOF")
	}
	line = strings.TrimRight(s.Text(), "\r")
	username, ok := strings.CutPrefix(line, "USER:")
	if !ok {
		return nil, fmt.Errorf("expected USER: line, got %q", line)
	}
	if username == "" {
		return nil, fmt.Errorf("empty username in USER line")
	}

	// Line 3: END
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return nil, fmt.Errorf("read END line: %w", err)
		}
		return nil, fmt.Errorf("read END line: unexpected EOF")
	}
	line = strings.TrimRight(s.Text(), "\r")
	if line != "END" {
		return nil, fmt.Errorf("expected END, got %q", line)
	}

	return &authSignal{Version: version, Username: username}, nil
}
