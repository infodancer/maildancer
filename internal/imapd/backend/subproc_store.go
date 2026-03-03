package backend

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infodancer/maildancer/msgstore"
)

const (
	// maxMessageSize caps message body allocations to prevent OOM from a
	// compromised or buggy mail-session subprocess.
	maxMessageSize int64 = 52 * 1024 * 1024 // 50 MiB

	// maxMessageCount caps the number of lines read in a +OK <n> response.
	maxMessageCount = 1_000_000
)

// validateProtocolArg rejects strings that could corrupt the pipe protocol.
// The protocol uses space as argument delimiter, so spaces are also rejected.
func validateProtocolArg(s string) error {
	if strings.ContainsAny(s, "\r\n\x00 ") {
		return fmt.Errorf("invalid argument: contains disallowed characters")
	}
	return nil
}

// Compile-time assertion: SubprocessStore must satisfy the mover interface
// defined in storeops.go so that Move uses the atomic path.
var _ mover = (*SubprocessStore)(nil)

// SubprocessStore implements msgstore.MessageStore and msgstore.FolderStore by
// speaking the mail-session pipe protocol. A mutex serialises all protocol I/O.
type SubprocessStore struct {
	r             *bufio.Reader
	w             *bufio.Writer
	cleanup       func() error // called by Close; nil in tests
	mailbox       string
	mu            sync.Mutex
	currentFolder string // "" == INBOX (default after MAILBOX)
	closed        bool
}

// newSubprocessStoreFromPipes creates a SubprocessStore using explicit
// io.Reader/io.Writer pairs. Sends MAILBOX <mailbox> and reads +OK before returning.
// Used by tests to inject mock pipe ends without a real subprocess.
func newSubprocessStoreFromPipes(r io.Reader, w io.Writer, cleanup func() error, mailbox string) (*SubprocessStore, error) {
	s := &SubprocessStore{
		r:       bufio.NewReader(r),
		w:       bufio.NewWriter(w),
		cleanup: cleanup,
		mailbox: mailbox,
	}
	if err := s.sendCmd("MAILBOX " + mailbox); err != nil {
		return nil, fmt.Errorf("send MAILBOX: %w", err)
	}
	if err := s.readOK(); err != nil {
		return nil, fmt.Errorf("MAILBOX response: %w", err)
	}
	return s, nil
}

// NewSubprocessStore starts cmd and creates a SubprocessStore over its stdin/stdout pipes.
func NewSubprocessStore(cmd *exec.Cmd, mailbox string) (*SubprocessStore, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start mail-session: %w", err)
	}
	cleanup := func() error {
		_ = stdin.Close()
		return cmd.Wait()
	}
	s, err := newSubprocessStoreFromPipes(stdout, stdin, cleanup, mailbox)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = stdin.Close()
		_ = cmd.Wait()
		return nil, err
	}
	return s, nil
}

// Close sends QUIT to mail-session and waits for it to exit.
func (s *SubprocessStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.sendCmd("QUIT")
	if s.cleanup != nil {
		return s.cleanup()
	}
	return nil
}

// -- Internal protocol helpers (caller must hold mu) --

// sendCmd writes a single CRLF-terminated command line and flushes.
func (s *SubprocessStore) sendCmd(line string) error {
	_, err := fmt.Fprintf(s.w, "%s\r\n", line)
	if err != nil {
		return err
	}
	return s.w.Flush()
}

// readLine reads one LF-terminated response line and trims CR/LF.
func (s *SubprocessStore) readLine() (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readOK reads a line and returns nil iff it equals "+OK".
func (s *SubprocessStore) readOK() error {
	line, err := s.readLine()
	if err != nil {
		return err
	}
	if line == "+OK" {
		return nil
	}
	if rest, ok := strings.CutPrefix(line, "-ERR"); ok {
		return fmt.Errorf("mail-session: %s", strings.TrimPrefix(rest, " "))
	}
	return fmt.Errorf("unexpected response: %q", line)
}

// readOKData reads "+OK <data>" and returns the data portion.
func (s *SubprocessStore) readOKData() (string, error) {
	line, err := s.readLine()
	if err != nil {
		return "", err
	}
	if data, ok := strings.CutPrefix(line, "+OK "); ok {
		return data, nil
	}
	if line == "+OK" {
		return "", nil
	}
	if rest, ok := strings.CutPrefix(line, "-ERR"); ok {
		return "", fmt.Errorf("mail-session: %s", strings.TrimPrefix(rest, " "))
	}
	return "", fmt.Errorf("unexpected response: %q", line)
}

// readOKLines reads "+OK <n>" then n following lines.
func (s *SubprocessStore) readOKLines() ([]string, error) {
	data, err := s.readOKData()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return nil, fmt.Errorf("missing count in +OK response")
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("invalid count %q: %w", fields[0], err)
	}
	if n < 0 || n > maxMessageCount {
		return nil, fmt.Errorf("message count %d out of range", n)
	}
	lines := make([]string, n)
	for i := range n {
		lines[i], err = s.readLine()
		if err != nil {
			return nil, fmt.Errorf("reading line %d of %d: %w", i+1, n, err)
		}
	}
	return lines, nil
}

// readData reads "+DATA <size>" then exactly size bytes.
func (s *SubprocessStore) readData() ([]byte, error) {
	line, err := s.readLine()
	if err != nil {
		return nil, err
	}
	if rest, ok := strings.CutPrefix(line, "-ERR"); ok {
		return nil, fmt.Errorf("mail-session: %s", strings.TrimPrefix(rest, " "))
	}
	sizeStr, ok := strings.CutPrefix(line, "+DATA ")
	if !ok {
		return nil, fmt.Errorf("expected +DATA, got %q", line)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size in +DATA %q: %w", sizeStr, err)
	}
	if size < 0 || size > maxMessageSize {
		return nil, fmt.Errorf("message size %d out of range", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, fmt.Errorf("reading data bytes: %w", err)
	}
	return buf, nil
}

// ensureFolderLocked sends SELECT <folder> if the current context differs.
// "" and "INBOX" are treated as equivalent (default context after MAILBOX).
// Discards the SELECT message list — callers that need it call SELECT directly.
// Caller must hold mu.
func (s *SubprocessStore) ensureFolderLocked(folder string) error {
	if folder == "" {
		folder = "INBOX"
	}
	want := strings.ToUpper(folder)
	current := strings.ToUpper(s.currentFolder)
	if current == "" {
		current = "INBOX"
	}
	if want == current {
		return nil
	}
	if err := s.sendCmd("SELECT " + folder); err != nil {
		return err
	}
	if _, err := s.readOKLines(); err != nil {
		return fmt.Errorf("SELECT %s: %w", folder, err)
	}
	s.currentFolder = folder
	return nil
}

// parseMessageInfos parses lines of the form "<uid> <size> [flag1 flag2...]".
func parseMessageInfos(lines []string) []msgstore.MessageInfo {
	msgs := make([]msgstore.MessageInfo, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		info := msgstore.MessageInfo{
			UID:  fields[0],
			Size: size,
		}
		if len(fields) > 2 {
			info.Flags = fields[2:]
		}
		msgs = append(msgs, info)
	}
	return msgs
}

// parseStatData parses "<count> <totalBytes>" from a STAT +OK data string.
func parseStatData(data string) (int, int64, error) {
	fields := strings.Fields(data)
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("invalid STAT response: %q", data)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid count in STAT: %w", err)
	}
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid total in STAT: %w", err)
	}
	return count, total, nil
}

// -- msgstore.MessageStore --

func (s *SubprocessStore) List(_ context.Context, _ string) ([]msgstore.MessageInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked("INBOX"); err != nil {
		return nil, err
	}
	if err := s.sendCmd("LIST"); err != nil {
		return nil, err
	}
	lines, err := s.readOKLines()
	if err != nil {
		return nil, err
	}
	return parseMessageInfos(lines), nil
}

func (s *SubprocessStore) Retrieve(_ context.Context, _ string, uid string) (io.ReadCloser, error) {
	if err := validateProtocolArg(uid); err != nil {
		return nil, fmt.Errorf("uid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked("INBOX"); err != nil {
		return nil, err
	}
	if err := s.sendCmd("GET " + uid); err != nil {
		return nil, err
	}
	data, err := s.readData()
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Delete marks a message for deletion by setting the \Deleted flag.
// Uses IMAP flag semantics; call Expunge to permanently remove.
func (s *SubprocessStore) Delete(_ context.Context, _ string, uid string) error {
	if err := validateProtocolArg(uid); err != nil {
		return fmt.Errorf("uid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked("INBOX"); err != nil {
		return err
	}
	if err := s.sendCmd(`SETFLAGS ` + uid + ` \Deleted`); err != nil {
		return err
	}
	return s.readOK()
}

func (s *SubprocessStore) Expunge(_ context.Context, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked("INBOX"); err != nil {
		return err
	}
	if err := s.sendCmd("EXPUNGE"); err != nil {
		return err
	}
	_, err := s.readOKLines()
	return err
}

func (s *SubprocessStore) Stat(_ context.Context, _ string) (int, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked("INBOX"); err != nil {
		return 0, 0, err
	}
	if err := s.sendCmd("STAT"); err != nil {
		return 0, 0, err
	}
	data, err := s.readOKData()
	if err != nil {
		return 0, 0, err
	}
	return parseStatData(data)
}

// -- msgstore.FolderStore --

func (s *SubprocessStore) CreateFolder(_ context.Context, _ string, folder string) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sendCmd("CREATEFOLDER " + folder); err != nil {
		return err
	}
	return s.readOK()
}

func (s *SubprocessStore) ListFolders(_ context.Context, _ string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sendCmd("FOLDERS"); err != nil {
		return nil, err
	}
	return s.readOKLines()
}

func (s *SubprocessStore) DeleteFolder(_ context.Context, _ string, folder string) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sendCmd("DELETEFOLDER " + folder); err != nil {
		return err
	}
	if strings.EqualFold(folder, s.currentFolder) {
		s.currentFolder = ""
	}
	return s.readOK()
}

// ListInFolder uses SELECT to both switch context and retrieve the message list
// in a single round-trip.
func (s *SubprocessStore) ListInFolder(_ context.Context, _ string, folder string) ([]msgstore.MessageInfo, error) {
	if err := validateProtocolArg(folder); err != nil {
		return nil, fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if folder == "" {
		folder = "INBOX"
	}
	if err := s.sendCmd("SELECT " + folder); err != nil {
		return nil, err
	}
	lines, err := s.readOKLines()
	if err != nil {
		return nil, fmt.Errorf("SELECT %s: %w", folder, err)
	}
	s.currentFolder = folder
	return parseMessageInfos(lines), nil
}

func (s *SubprocessStore) StatFolder(_ context.Context, _ string, folder string) (int, int64, error) {
	if err := validateProtocolArg(folder); err != nil {
		return 0, 0, fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(folder); err != nil {
		return 0, 0, err
	}
	if err := s.sendCmd("STAT"); err != nil {
		return 0, 0, err
	}
	data, err := s.readOKData()
	if err != nil {
		return 0, 0, err
	}
	return parseStatData(data)
}

func (s *SubprocessStore) RetrieveFromFolder(_ context.Context, _ string, folder string, uid string) (io.ReadCloser, error) {
	if err := validateProtocolArg(folder); err != nil {
		return nil, fmt.Errorf("folder: %w", err)
	}
	if err := validateProtocolArg(uid); err != nil {
		return nil, fmt.Errorf("uid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(folder); err != nil {
		return nil, err
	}
	if err := s.sendCmd("GET " + uid); err != nil {
		return nil, err
	}
	data, err := s.readData()
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *SubprocessStore) DeleteInFolder(_ context.Context, _ string, folder string, uid string) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	if err := validateProtocolArg(uid); err != nil {
		return fmt.Errorf("uid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(folder); err != nil {
		return err
	}
	if err := s.sendCmd(`SETFLAGS ` + uid + ` \Deleted`); err != nil {
		return err
	}
	return s.readOK()
}

func (s *SubprocessStore) ExpungeFolder(_ context.Context, _ string, folder string) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(folder); err != nil {
		return err
	}
	if err := s.sendCmd("EXPUNGE"); err != nil {
		return err
	}
	_, err := s.readOKLines()
	return err
}

// DeliverToFolder delivers a message to a folder with no flags and the current time.
func (s *SubprocessStore) DeliverToFolder(_ context.Context, _ string, folder string, r io.Reader) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(r, maxMessageSize+1))
	if err != nil {
		return fmt.Errorf("reading message body: %w", err)
	}
	if int64(len(body)) > maxMessageSize {
		return fmt.Errorf("message size exceeds maximum %d bytes", maxMessageSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("APPEND %s %d NONE %s", folder, len(body), time.Now().UTC().Format(time.RFC3339))
	if err := s.sendCmd(line); err != nil {
		return err
	}
	if _, err := s.w.Write(body); err != nil {
		return err
	}
	if err := s.w.Flush(); err != nil {
		return err
	}
	_, err = s.readOKData()
	return err
}

func (s *SubprocessStore) RenameFolder(_ context.Context, _ string, oldName string, newName string) error {
	if err := validateProtocolArg(oldName); err != nil {
		return fmt.Errorf("old name: %w", err)
	}
	if err := validateProtocolArg(newName); err != nil {
		return fmt.Errorf("new name: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sendCmd("RENAMEFOLDER " + oldName + " " + newName); err != nil {
		return err
	}
	if strings.EqualFold(s.currentFolder, oldName) {
		s.currentFolder = newName
	}
	return s.readOK()
}

// AppendToFolder stores a message with explicit flags and internal date.
// Flags are sent comma-separated (or NONE); date is RFC3339.
func (s *SubprocessStore) AppendToFolder(_ context.Context, _ string, folder string, r io.Reader, flags []string, date time.Time) (string, error) {
	if err := validateProtocolArg(folder); err != nil {
		return "", fmt.Errorf("folder: %w", err)
	}
	for _, f := range flags {
		if err := validateProtocolArg(f); err != nil {
			return "", fmt.Errorf("flag %q: %w", f, err)
		}
	}
	body, err := io.ReadAll(io.LimitReader(r, maxMessageSize+1))
	if err != nil {
		return "", fmt.Errorf("reading message body: %w", err)
	}
	if int64(len(body)) > maxMessageSize {
		return "", fmt.Errorf("message size exceeds maximum %d bytes", maxMessageSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	flagsStr := "NONE"
	if len(flags) > 0 {
		flagsStr = strings.Join(flags, ",")
	}
	line := fmt.Sprintf("APPEND %s %d %s %s", folder, len(body), flagsStr, date.UTC().Format(time.RFC3339))
	if err := s.sendCmd(line); err != nil {
		return "", err
	}
	if _, err := s.w.Write(body); err != nil {
		return "", err
	}
	if err := s.w.Flush(); err != nil {
		return "", err
	}
	uid, err := s.readOKData()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(uid), nil
}

// SetFlagsInFolder replaces the complete flag set on a message.
// Flags are sent as space-separated args after the UID.
func (s *SubprocessStore) SetFlagsInFolder(_ context.Context, _ string, folder string, uid string, flags []string) error {
	if err := validateProtocolArg(folder); err != nil {
		return fmt.Errorf("folder: %w", err)
	}
	if err := validateProtocolArg(uid); err != nil {
		return fmt.Errorf("uid: %w", err)
	}
	for _, f := range flags {
		if err := validateProtocolArg(f); err != nil {
			return fmt.Errorf("flag %q: %w", f, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(folder); err != nil {
		return err
	}
	cmd := "SETFLAGS " + uid
	if len(flags) > 0 {
		cmd += " " + strings.Join(flags, " ")
	}
	if err := s.sendCmd(cmd); err != nil {
		return err
	}
	return s.readOK()
}

func (s *SubprocessStore) CopyMessage(_ context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	if err := validateProtocolArg(srcFolder); err != nil {
		return "", fmt.Errorf("src folder: %w", err)
	}
	if err := validateProtocolArg(uid); err != nil {
		return "", fmt.Errorf("uid: %w", err)
	}
	if err := validateProtocolArg(destFolder); err != nil {
		return "", fmt.Errorf("dest folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFolderLocked(srcFolder); err != nil {
		return "", err
	}
	if err := s.sendCmd("COPY " + uid + " " + destFolder); err != nil {
		return "", err
	}
	newUID, err := s.readOKData()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(newUID), nil
}

// MoveMessage atomically moves a message from srcFolder to destFolder via the
// mail-session MOVE command. mail-session handles the copy+delete+expunge and
// triggers rspamd learning when either folder is Junk.
// Returns the new UID in destFolder.
func (s *SubprocessStore) MoveMessage(_ context.Context, _ string, srcFolder string, uid string, destFolder string) (string, error) {
	if err := validateProtocolArg(srcFolder); err != nil {
		return "", fmt.Errorf("src folder: %w", err)
	}
	if err := validateProtocolArg(uid); err != nil {
		return "", fmt.Errorf("uid: %w", err)
	}
	if err := validateProtocolArg(destFolder); err != nil {
		return "", fmt.Errorf("dest folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sendCmd("MOVE " + uid + " " + srcFolder + " " + destFolder); err != nil {
		return "", err
	}
	newUID, err := s.readOKData()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(newUID), nil
}

func (s *SubprocessStore) UIDValidity(_ context.Context, _ string, folder string) (uint32, error) {
	if err := validateProtocolArg(folder); err != nil {
		return 0, fmt.Errorf("folder: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if folder == "" {
		folder = "INBOX"
	}
	if err := s.sendCmd("UIDVALIDITY " + folder); err != nil {
		return 0, err
	}
	data, err := s.readOKData()
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(data), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid UIDVALIDITY response %q: %w", data, err)
	}
	return uint32(v), nil
}
