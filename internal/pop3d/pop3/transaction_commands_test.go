package pop3

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// mockMessageStore is a test double for MessageStore.
type mockMessageStore struct {
	messages    []msgstore.MessageInfo
	content     map[uint32]string // UID -> content
	deleted     map[uint32]bool
	listErr     error
	retrieveErr error
	deleteErr   error
	expungeErr  error
}

func newMockMessageStore() *mockMessageStore {
	return &mockMessageStore{
		messages: []msgstore.MessageInfo{
			{UID: 1, Size: 100},
			{UID: 2, Size: 200},
			{UID: 3, Size: 300},
		},
		content: map[uint32]string{
			1: "Subject: Test 1\r\n\r\nBody line 1\r\nBody line 2\r\n",
			2: "Subject: Test 2\r\n\r\nBody of message 2\r\n",
			3: "Subject: Test 3\r\nFrom: test@example.com\r\n\r\nLine 1\r\nLine 2\r\nLine 3\r\n",
		},
		deleted: make(map[uint32]bool),
	}
}

func (m *mockMessageStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.messages, nil
}

func (m *mockMessageStore) Retrieve(ctx context.Context, mailbox string, uid uint32) (io.ReadCloser, error) {
	if m.retrieveErr != nil {
		return nil, m.retrieveErr
	}
	content, ok := m.content[uid]
	if !ok {
		return nil, ErrNoSuchMessage
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (m *mockMessageStore) Delete(ctx context.Context, mailbox string, uid uint32) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deleted[uid] = true
	return nil
}

func (m *mockMessageStore) Expunge(ctx context.Context, mailbox string) error {
	return m.expungeErr
}

func (m *mockMessageStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	var total int64
	for _, msg := range m.messages {
		total += msg.Size
	}
	return len(m.messages), total, nil
}

// Helper to create a session in TRANSACTION state with messages loaded
func newTransactionSession(store msgstore.MessageStore) *Session {
	sess := NewSession("test.example.com", config.ModePop3s, nil, true)
	sess.SetAuthenticated(AuthenticatedUser{
		Username: "testuser",
		Mailbox:  "/var/mail/testuser",
	})
	if store != nil {
		_ = sess.InitializeMailbox(context.Background(), store, "")
	}
	return sess
}

func TestStatCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "STAT in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "STAT with arguments fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"extra"},
			wantOK:      false,
			wantMessage: "STAT command takes no arguments",
		},
		{
			name:        "STAT succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      true,
			wantMessage: "3 600", // 3 messages, 600 bytes total
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &statCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}
		})
	}
}

func TestListCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
		wantLines   int
	}{
		{
			name:        "LIST in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "LIST all messages succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      true,
			wantMessage: "3 messages (600 octets)",
			wantLines:   3,
		},
		{
			name:        "LIST specific message succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1"},
			wantOK:      true,
			wantMessage: "1 100",
		},
		{
			name:        "LIST invalid message number fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"99"},
			wantOK:      false,
			wantMessage: "No such message",
		},
		{
			name:        "LIST non-numeric argument fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"abc"},
			wantOK:      false,
			wantMessage: "Invalid message number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &listCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}

			if tt.wantLines > 0 && len(resp.Lines) != tt.wantLines {
				t.Errorf("Execute() Lines count = %d, want %d", len(resp.Lines), tt.wantLines)
			}
		})
	}
}

func TestRetrCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
		wantLines   bool
	}{
		{
			name:        "RETR in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"1"},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "RETR without argument fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      false,
			wantMessage: "RETR command requires message number",
		},
		{
			name:        "RETR succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1"},
			wantOK:      true,
			wantMessage: "100 octets",
			wantLines:   true,
		},
		{
			name:        "RETR invalid message fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"99"},
			wantOK:      false,
			wantMessage: "No such message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &retrCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}

			if tt.wantLines && len(resp.Lines) == 0 {
				t.Error("Execute() expected Lines, got none")
			}
		})
	}
}

func TestDeleCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "DELE in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"1"},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "DELE without argument fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      false,
			wantMessage: "DELE command requires message number",
		},
		{
			name:        "DELE succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1"},
			wantOK:      true,
			wantMessage: "message 1 deleted",
		},
		{
			name:        "DELE invalid message fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"99"},
			wantOK:      false,
			wantMessage: "No such message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &deleCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}
		})
	}
}

func TestDeleAlreadyDeleted(t *testing.T) {
	sess := newTransactionSession(newMockMessageStore())
	cmd := &deleCommand{}

	// First delete should succeed
	resp, _ := cmd.Execute(context.Background(), sess, newMockConnection(), []string{"1"})
	if !resp.OK {
		t.Fatal("First DELE should succeed")
	}

	// Second delete of same message should fail
	resp, _ = cmd.Execute(context.Background(), sess, newMockConnection(), []string{"1"})
	if resp.OK {
		t.Error("DELE of already deleted message should fail")
	}
	if resp.Message != "Message already deleted" {
		t.Errorf("Expected 'Message already deleted', got %q", resp.Message)
	}
}

func TestRsetCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "RSET in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "RSET with arguments fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"extra"},
			wantOK:      false,
			wantMessage: "RSET command takes no arguments",
		},
		{
			name:        "RSET succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      true,
			wantMessage: "maildrop has 3 messages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &rsetCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}
		})
	}
}

func TestRsetRestoresDeletions(t *testing.T) {
	sess := newTransactionSession(newMockMessageStore())
	deleCmd := &deleCommand{}
	rsetCmd := &rsetCommand{}
	statCmd := &statCommand{}

	// Initial count
	resp, _ := statCmd.Execute(context.Background(), sess, newMockConnection(), []string{})
	if resp.Message != "3 600" {
		t.Fatalf("Expected 3 messages initially, got %q", resp.Message)
	}

	// Delete a message
	_, err := deleCmd.Execute(context.Background(), sess, newMockConnection(), []string{"1"})
	if err != nil {
		t.Fatalf("DELE failed: %v", err)
	}

	// Count after delete
	resp, _ = statCmd.Execute(context.Background(), sess, newMockConnection(), []string{})
	if resp.Message != "2 500" {
		t.Fatalf("Expected 2 messages after DELE, got %q", resp.Message)
	}

	// RSET
	_, err = rsetCmd.Execute(context.Background(), sess, newMockConnection(), []string{})
	if err != nil {
		t.Fatalf("RSET failed: %v", err)
	}

	// Count after RSET
	resp, _ = statCmd.Execute(context.Background(), sess, newMockConnection(), []string{})
	if resp.Message != "3 600" {
		t.Errorf("Expected 3 messages after RSET, got %q", resp.Message)
	}
}

func TestNoopCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "NOOP in AUTHORIZATION state succeeds",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      true,
			wantMessage: "",
		},
		{
			name:        "NOOP in TRANSACTION state succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      true,
			wantMessage: "",
		},
		{
			name:        "NOOP with arguments fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"extra"},
			wantOK:      false,
			wantMessage: "NOOP command takes no arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &noopCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}
		})
	}
}

func TestUidlCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
		wantLines   int
	}{
		{
			name:        "UIDL in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "UIDL all messages succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      true,
			wantMessage: "",
			wantLines:   3,
		},
		{
			name:        "UIDL specific message succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1"},
			wantOK:      true,
			wantMessage: "1 1",
		},
		{
			name:        "UIDL invalid message fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"99"},
			wantOK:      false,
			wantMessage: "No such message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &uidlCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}

			if tt.wantLines > 0 && len(resp.Lines) != tt.wantLines {
				t.Errorf("Execute() Lines count = %d, want %d", len(resp.Lines), tt.wantLines)
			}
		})
	}
}

func TestTopCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
		wantLines   int
	}{
		{
			name:        "TOP in AUTHORIZATION state fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"1", "0"},
			wantOK:      false,
			wantMessage: "Command not valid in this state",
		},
		{
			name:        "TOP without arguments fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{},
			wantOK:      false,
			wantMessage: "TOP command requires message number and line count",
		},
		{
			name:        "TOP with one argument fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1"},
			wantOK:      false,
			wantMessage: "TOP command requires message number and line count",
		},
		{
			name:        "TOP with 0 lines succeeds (headers only)",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1", "0"},
			wantOK:      true,
			wantMessage: "",
			wantLines:   2, // Subject header + empty line
		},
		{
			name:        "TOP with lines succeeds",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"3", "2"},
			wantOK:      true,
			wantMessage: "",
			wantLines:   5, // 2 headers + empty line + 2 body lines
		},
		{
			name:        "TOP invalid message fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"99", "5"},
			wantOK:      false,
			wantMessage: "No such message",
		},
		{
			name:        "TOP negative line count fails",
			sess:        newTransactionSession(newMockMessageStore()),
			args:        []string{"1", "-1"},
			wantOK:      false,
			wantMessage: "Invalid line count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &topCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, newMockConnection(), tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %q, want %q", resp.Message, tt.wantMessage)
			}

			if tt.wantLines > 0 && len(resp.Lines) != tt.wantLines {
				t.Errorf("Execute() Lines count = %d, want %d (lines: %v)", len(resp.Lines), tt.wantLines, resp.Lines)
			}
		})
	}
}

func TestDeletedMessageExcludedFromList(t *testing.T) {
	sess := newTransactionSession(newMockMessageStore())
	deleCmd := &deleCommand{}
	listCmd := &listCommand{}

	// Delete message 2
	_, err := deleCmd.Execute(context.Background(), sess, newMockConnection(), []string{"2"})
	if err != nil {
		t.Fatalf("DELE failed: %v", err)
	}

	// LIST should only show 2 messages
	resp, _ := listCmd.Execute(context.Background(), sess, newMockConnection(), []string{})
	if len(resp.Lines) != 2 {
		t.Errorf("Expected 2 lines after deleting one message, got %d", len(resp.Lines))
	}

	// Verify the remaining messages are 1 and 3
	expectedLines := []string{"1 100", "3 300"}
	for i, line := range resp.Lines {
		if line != expectedLines[i] {
			t.Errorf("Line %d = %q, want %q", i, line, expectedLines[i])
		}
	}

	// LIST specific deleted message should fail
	resp, _ = listCmd.Execute(context.Background(), sess, newMockConnection(), []string{"2"})
	if resp.OK {
		t.Error("LIST of deleted message should fail")
	}
}

func TestTransactionCommandRegistry(t *testing.T) {
	// Clear the registry first
	commandRegistry = make(map[string]Command)

	// Register transaction commands
	RegisterTransactionCommands()

	tests := []struct {
		name      string
		cmdName   string
		wantFound bool
	}{
		{"STAT exists", "STAT", true},
		{"LIST exists", "LIST", true},
		{"RETR exists", "RETR", true},
		{"DELE exists", "DELE", true},
		{"RSET exists", "RSET", true},
		{"NOOP exists", "NOOP", true},
		{"UIDL exists", "UIDL", true},
		{"TOP exists", "TOP", true},
		{"stat exists (case insensitive)", "stat", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, found := GetCommand(tt.cmdName)

			if found != tt.wantFound {
				t.Errorf("GetCommand(%q) found = %v, want %v", tt.cmdName, found, tt.wantFound)
			}

			if tt.wantFound && cmd == nil {
				t.Errorf("GetCommand(%q) returned nil command", tt.cmdName)
			}
		})
	}
}

func TestSplitMessageLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "CRLF line endings",
			content: "line1\r\nline2\r\nline3\r\n",
			want:    []string{"line1", "line2", "line3"},
		},
		{
			name:    "LF line endings",
			content: "line1\nline2\nline3\n",
			want:    []string{"line1", "line2", "line3"},
		},
		{
			name:    "Mixed line endings",
			content: "line1\r\nline2\nline3\r\n",
			want:    []string{"line1", "line2", "line3"},
		},
		{
			name:    "No trailing newline",
			content: "line1\r\nline2",
			want:    []string{"line1", "line2"},
		},
		{
			name:    "Empty content",
			content: "",
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitMessageLines(tt.content)
			if len(got) != len(tt.want) {
				t.Errorf("splitMessageLines() = %v (len %d), want %v (len %d)", got, len(got), tt.want, len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitMessageLines()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
