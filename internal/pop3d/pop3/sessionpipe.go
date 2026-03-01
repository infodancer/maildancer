package pop3

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/infodancer/maildancer/msgstore"
)

// Compile-time assertion that sessionPipeStore satisfies msgstore.MessageStore.
var _ msgstore.MessageStore = (*sessionPipeStore)(nil)

// maxListCount is a sanity cap on the number of messages a mail-session may
// report. A legitimate mailbox will never approach this; the limit prevents
// a compromised mail-session from causing an OOM allocation.
const maxListCount = 10_000_000

// sessionPipeStore implements msgstore.MessageStore by routing all operations
// through the session pipe protocol (fds 5 and 6 in the protocol-handler).
//
// On the first List call it writes the auth signal to the auth pipe (fd 4),
// closes that pipe so the dispatcher can unblock, then performs the MAILBOX
// handshake with mail-session before executing the LIST.
//
// The auth pipe (fd 4) is always closed exactly once, even on error, so the
// dispatcher never blocks indefinitely. A failed handshake is terminal: the
// store records the failure and all subsequent calls return an error.
type sessionPipeStore struct {
	authPipeW    io.WriteCloser // fd 4: written once, then closed
	sessR        *bufio.Reader  // fd 5: responses from mail-session
	sessW        io.Writer      // fd 6: commands to mail-session
	ready        bool           // true once handshake succeeded
	handshakeDone bool          // true once handshake was attempted (win or lose)
}

// NewSessionPipeStore creates a sessionPipeStore from the three pipe ends used
// in the subprocess protocol-handler.
func NewSessionPipeStore(authPipeW io.WriteCloser, sessR io.Reader, sessW io.Writer) msgstore.MessageStore {
	return &sessionPipeStore{
		authPipeW: authPipeW,
		sessR:     bufio.NewReader(sessR),
		sessW:     sessW,
	}
}

// validateToken returns an error if s contains whitespace or control
// characters that would break the line-oriented wire protocol.
func validateToken(label, s string) error {
	if s == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("%s contains illegal whitespace", label)
	}
	return nil
}

// handshake writes the auth signal to fd 4 and performs the MAILBOX exchange
// with mail-session. It always closes authPipeW so the dispatcher can unblock.
// After handshake returns (success or failure) handshakeDone is true and the
// method must not be called again.
func (p *sessionPipeStore) handshake(mailbox string) (retErr error) {
	p.handshakeDone = true

	// Always close the auth pipe so the dispatcher unblocks on EOF, even if
	// the write fails or a later step fails.
	defer func() {
		if err := p.authPipeW.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close auth pipe: %w", err)
		}
	}()

	if err := validateToken("mailbox", mailbox); err != nil {
		return err
	}

	// The mailbox is also the fully-qualified username (localpart@domain) per the
	// address contract: AuthRouter guarantees User.Mailbox == base@domain.
	sig := &authSignal{Version: 1, Username: mailbox}
	if err := writeAuthSignal(p.authPipeW, sig); err != nil {
		return fmt.Errorf("write auth signal: %w", err)
	}

	if _, err := fmt.Fprintf(p.sessW, "MAILBOX %s\r\n", mailbox); err != nil {
		return fmt.Errorf("send MAILBOX: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read MAILBOX response: %w", err)
	}
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), "+OK") {
		return fmt.Errorf("MAILBOX rejected: %s", strings.TrimRight(line, "\r\n"))
	}

	p.ready = true
	return nil
}

// ensureReady runs the handshake on the first call and returns an error if the
// handshake already failed.
func (p *sessionPipeStore) ensureReady(mailbox string) error {
	if p.ready {
		return nil
	}
	if p.handshakeDone {
		// Handshake was already attempted and failed; the store is not usable.
		return fmt.Errorf("session pipe handshake already failed; store is not usable")
	}
	return p.handshake(mailbox)
}

// readOK reads one response line and returns an error if it is not "+OK …".
func (p *sessionPipeStore) readOK(op string) error {
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return fmt.Errorf("%s: read response: %w", op, err)
	}
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), "+OK") {
		return fmt.Errorf("%s error: %s", op, strings.TrimRight(line, "\r\n"))
	}
	return nil
}

// List implements msgstore.MessageStore.
// On the first call it performs the auth/MAILBOX handshake.
// Wire: send "LIST\r\n"; receive "+OK <count> <octets>\r\n" then <count> lines
// of "<uid> <size>\r\n".
func (p *sessionPipeStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	if err := p.ensureReady(mailbox); err != nil {
		return nil, err
	}

	if _, err := fmt.Fprintf(p.sessW, "LIST\r\n"); err != nil {
		return nil, fmt.Errorf("send LIST: %w", err)
	}

	// "+OK <count> <octets>"
	header, err := p.sessR.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read LIST header: %w", err)
	}
	header = strings.TrimRight(header, "\r\n")
	if !strings.HasPrefix(header, "+OK") {
		return nil, fmt.Errorf("LIST error: %s", header)
	}

	// Parse message count from "+OK <count> …"
	fields := strings.Fields(strings.TrimPrefix(header, "+OK"))
	if len(fields) == 0 {
		return nil, fmt.Errorf("LIST: missing count in %q", header)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("LIST: invalid count %q", fields[0])
	}
	if count < 0 || count > maxListCount {
		return nil, fmt.Errorf("LIST: unreasonable count %d", count)
	}

	msgs := make([]msgstore.MessageInfo, 0, count)
	for i := range count {
		entry, err := p.sessR.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("LIST entry %d: %w", i+1, err)
		}
		entry = strings.TrimRight(entry, "\r\n")
		// "<uid> <size> [flags…]" — flags are optional; ignore extra fields.
		f := strings.Fields(entry)
		if len(f) < 2 {
			return nil, fmt.Errorf("LIST entry %d: malformed %q", i+1, entry)
		}
		size, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("LIST entry %d: invalid size %q", i+1, f[1])
		}
		msgs = append(msgs, msgstore.MessageInfo{UID: f[0], Size: size})
	}
	return msgs, nil
}

// drainingCloser wraps an io.Reader and drains any unread bytes on Close so
// that the shared sessR stays synchronised for subsequent protocol messages.
type drainingCloser struct {
	r io.Reader
}

func (d *drainingCloser) Read(p []byte) (int, error) { return d.r.Read(p) }
func (d *drainingCloser) Close() error {
	_, _ = io.Copy(io.Discard, d.r)
	return nil
}

// Retrieve implements msgstore.MessageStore.
// Wire: send "GET <uid>\r\n"; receive "+DATA <size>\r\n" then exactly <size> bytes.
// Close() on the returned ReadCloser drains any unread bytes so the shared
// pipe reader stays synchronised for subsequent operations.
func (p *sessionPipeStore) Retrieve(ctx context.Context, mailbox, uid string) (io.ReadCloser, error) {
	if err := validateToken("uid", uid); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(p.sessW, "GET %s\r\n", uid); err != nil {
		return nil, fmt.Errorf("send GET: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read GET response: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+DATA") {
		return nil, fmt.Errorf("GET error: %s", line)
	}
	sizeStr := strings.TrimSpace(strings.TrimPrefix(line, "+DATA"))
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GET: invalid data size %q", sizeStr)
	}
	// Wrap in a drainingCloser so that callers that stop reading early (e.g. TOP)
	// do not leave unread bytes in sessR to corrupt the next protocol exchange.
	return &drainingCloser{r: io.LimitReader(p.sessR, size)}, nil
}

// Delete implements msgstore.MessageStore.
// Wire: send "DELETE <uid>\r\n"; receive "+OK\r\n".
func (p *sessionPipeStore) Delete(ctx context.Context, mailbox, uid string) error {
	if err := validateToken("uid", uid); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.sessW, "DELETE %s\r\n", uid); err != nil {
		return fmt.Errorf("send DELETE: %w", err)
	}
	return p.readOK("DELETE")
}

// Expunge implements msgstore.MessageStore.
// Sends COMMIT which causes mail-session to apply all pending deletions.
// Wire: send "COMMIT\r\n"; receive "+OK\r\n".
func (p *sessionPipeStore) Expunge(ctx context.Context, mailbox string) error {
	if err := p.ensureReady(mailbox); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.sessW, "COMMIT\r\n"); err != nil {
		return fmt.Errorf("send COMMIT: %w", err)
	}
	return p.readOK("COMMIT")
}

// Stat implements msgstore.MessageStore.
// Wire: send "STAT\r\n"; receive "+OK <count> <octets>\r\n".
func (p *sessionPipeStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	if err := p.ensureReady(mailbox); err != nil {
		return 0, 0, err
	}
	if _, err := fmt.Fprintf(p.sessW, "STAT\r\n"); err != nil {
		return 0, 0, fmt.Errorf("send STAT: %w", err)
	}
	line, err := p.sessR.ReadString('\n')
	if err != nil {
		return 0, 0, fmt.Errorf("read STAT response: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+OK") {
		return 0, 0, fmt.Errorf("STAT error: %s", line)
	}
	// "+OK <count> <octets>"
	fields := strings.Fields(strings.TrimPrefix(line, "+OK"))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("STAT: malformed response %q", line)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, fmt.Errorf("STAT: invalid count %q", fields[0])
	}
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("STAT: invalid total %q", fields[1])
	}
	return count, total, nil
}
