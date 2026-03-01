package pop3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

// pipeHarness wires a sessionPipeStore to in-memory buffers so tests can
// inject canned responses and inspect the commands sent by the store.
type pipeHarness struct {
	store   *sessionPipeStore
	authBuf *bytes.Buffer // captures auth signal written to authPipeW
	cmdBuf  *bytes.Buffer // captures commands sent to sessW
	respBuf *bytes.Buffer // supplies canned responses to sessR
	closed  bool          // set when authPipeW.Close() is called
}

type closingBuffer struct {
	buf    *bytes.Buffer
	closed *bool
}

func (c *closingBuffer) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *closingBuffer) Close() error                { *c.closed = true; return nil }

// newHarness creates a harness pre-loaded with the given response text.
// Responses are consumed in order by the store as it reads from sessR.
func newHarness(responses string) *pipeHarness {
	h := &pipeHarness{
		authBuf: &bytes.Buffer{},
		cmdBuf:  &bytes.Buffer{},
		respBuf: bytes.NewBufferString(responses),
	}
	cb := &closingBuffer{buf: h.authBuf, closed: &h.closed}
	h.store = NewSessionPipeStore(cb, h.respBuf, h.cmdBuf).(*sessionPipeStore)
	return h
}

// TestSessionPipeStore_List verifies auth handshake + LIST wire framing.
func TestSessionPipeStore_List(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" + // MAILBOX response
			"+OK 2 1280\r\n" + // LIST header: 2 messages
			"abc123 512\r\n" + // entry 1
			"def456 768\r\n", // entry 2
	)

	msgs, err := h.store.List(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].UID != "abc123" || msgs[0].Size != 512 {
		t.Errorf("msg[0]: uid=%q size=%d", msgs[0].UID, msgs[0].Size)
	}
	if msgs[1].UID != "def456" || msgs[1].Size != 768 {
		t.Errorf("msg[1]: uid=%q size=%d", msgs[1].UID, msgs[1].Size)
	}

	// Auth signal written and pipe closed.
	authWritten := h.authBuf.String()
	if !strings.Contains(authWritten, "AUTH 1\r\n") {
		t.Errorf("auth signal missing AUTH line: %q", authWritten)
	}
	if !strings.Contains(authWritten, "USER:user@example.com\r\n") {
		t.Errorf("auth signal missing USER line: %q", authWritten)
	}
	if !strings.Contains(authWritten, "END\r\n") {
		t.Errorf("auth signal missing END line: %q", authWritten)
	}
	if !h.closed {
		t.Error("authPipeW.Close was not called")
	}

	// Commands sent to mail-session.
	cmds := h.cmdBuf.String()
	if !strings.Contains(cmds, "MAILBOX user@example.com\r\n") {
		t.Errorf("MAILBOX command not sent: %q", cmds)
	}
	if !strings.Contains(cmds, "LIST\r\n") {
		t.Errorf("LIST command not sent: %q", cmds)
	}
}

// TestSessionPipeStore_ListNoRepeatHandshake verifies the handshake runs only once.
func TestSessionPipeStore_ListNoRepeatHandshake(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" + // MAILBOX (handshake)
			"+OK 0 0\r\n" + // LIST #1
			"+OK 0 0\r\n", // LIST #2
	)

	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("first List: %v", err)
	}
	h.cmdBuf.Reset()

	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("second List: %v", err)
	}

	if strings.Contains(h.cmdBuf.String(), "MAILBOX") {
		t.Error("MAILBOX was sent again on second List call")
	}
}

// TestSessionPipeStore_ListWithFlags verifies that optional flag fields in LIST
// entries (e.g. "\Seen") are ignored rather than causing a parse error.
func TestSessionPipeStore_ListWithFlags(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"+OK 2 1280\r\n" +
			"abc123 512 \\Seen\r\n" +
			"def456 768 \\Seen \\Answered\r\n",
	)
	msgs, err := h.store.List(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].UID != "abc123" || msgs[0].Size != 512 {
		t.Errorf("msg[0]: uid=%q size=%d", msgs[0].UID, msgs[0].Size)
	}
	if msgs[1].UID != "def456" || msgs[1].Size != 768 {
		t.Errorf("msg[1]: uid=%q size=%d", msgs[1].UID, msgs[1].Size)
	}
}

// TestSessionPipeStore_ListEmpty verifies zero-message response.
func TestSessionPipeStore_ListEmpty(t *testing.T) {
	h := newHarness("+OK mailbox ready\r\n" + "+OK 0 0\r\n")
	msgs, err := h.store.List(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

// TestSessionPipeStore_Retrieve verifies GET wire framing and data delivery.
func TestSessionPipeStore_Retrieve(t *testing.T) {
	body := "From: test@example.com\r\nSubject: hello\r\n\r\nworld\r\n"
	h := newHarness(
		"+OK mailbox ready\r\n" + // MAILBOX
			"+OK 0 0\r\n" + // LIST (handshake)
			fmt.Sprintf("+DATA %d\r\n", len(body)) + // GET header
			body,
	)
	ctx := context.Background()

	// Trigger handshake.
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	h.cmdBuf.Reset()

	rc, err := h.store.Retrieve(ctx, "user@example.com", "abc123")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != body {
		t.Errorf("body mismatch\nwant: %q\ngot:  %q", body, string(got))
	}
	if !strings.Contains(h.cmdBuf.String(), "GET abc123\r\n") {
		t.Errorf("GET command not sent: %q", h.cmdBuf.String())
	}
}

// TestSessionPipeStore_Delete verifies DELETE wire framing.
func TestSessionPipeStore_Delete(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"+OK 0 0\r\n" + // LIST
			"+OK deleted\r\n", // DELETE
	)
	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	h.cmdBuf.Reset()

	if err := h.store.Delete(ctx, "user@example.com", "abc123"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !strings.Contains(h.cmdBuf.String(), "DELETE abc123\r\n") {
		t.Errorf("DELETE command not sent: %q", h.cmdBuf.String())
	}
}

// TestSessionPipeStore_Expunge verifies COMMIT wire framing.
func TestSessionPipeStore_Expunge(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"+OK 0 0\r\n" + // LIST
			"+OK committed\r\n", // COMMIT
	)
	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	h.cmdBuf.Reset()

	if err := h.store.Expunge(ctx, "user@example.com"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if !strings.Contains(h.cmdBuf.String(), "COMMIT\r\n") {
		t.Errorf("COMMIT command not sent: %q", h.cmdBuf.String())
	}
}

// TestSessionPipeStore_Stat verifies STAT wire framing and parsing.
func TestSessionPipeStore_Stat(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"+OK 0 0\r\n" + // LIST
			"+OK 3 4096\r\n", // STAT
	)
	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	h.cmdBuf.Reset()

	count, total, err := h.store.Stat(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 3 {
		t.Errorf("count: want 3, got %d", count)
	}
	if total != 4096 {
		t.Errorf("total: want 4096, got %d", total)
	}
	if !strings.Contains(h.cmdBuf.String(), "STAT\r\n") {
		t.Errorf("STAT command not sent: %q", h.cmdBuf.String())
	}
}

// TestSessionPipeStore_ListErrorResponse verifies -ERR propagation.
func TestSessionPipeStore_ListErrorResponse(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"-ERR mailbox locked\r\n",
	)
	_, err := h.store.List(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error on -ERR LIST response, got nil")
	}
}

// TestSessionPipeStore_MailboxRejected verifies -ERR on MAILBOX propagation.
func TestSessionPipeStore_MailboxRejected(t *testing.T) {
	h := newHarness("-ERR no such mailbox\r\n")
	_, err := h.store.List(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error on -ERR MAILBOX response, got nil")
	}
}

// TestSessionPipeStore_AuthSignalFormat verifies the exact wire format of the
// auth signal written to the auth pipe.
func TestSessionPipeStore_AuthSignalFormat(t *testing.T) {
	h := newHarness("+OK mailbox ready\r\n" + "+OK 0 0\r\n")
	if _, err := h.store.List(context.Background(), "alice@domain.example"); err != nil {
		t.Fatalf("List: %v", err)
	}
	want := "AUTH 1\r\nUSER:alice@domain.example\r\nEND\r\n"
	if got := h.authBuf.String(); got != want {
		t.Errorf("auth signal\nwant: %q\ngot:  %q", want, got)
	}
}

// TestSessionPipeStore_AuthPipeClosedOnHandshakeFailure verifies that the auth
// pipe is always closed, even when the MAILBOX response is -ERR. The dispatcher
// must receive EOF on the pipe to unblock; leaking it would hang the parent.
func TestSessionPipeStore_AuthPipeClosedOnHandshakeFailure(t *testing.T) {
	h := newHarness("-ERR mailbox rejected\r\n")
	_, _ = h.store.List(context.Background(), "user@example.com")
	if !h.closed {
		t.Error("authPipeW.Close was not called after handshake failure")
	}
}

// TestSessionPipeStore_HandshakeFailureTerminal verifies that after a failed
// handshake, subsequent List calls return an error rather than retrying.
func TestSessionPipeStore_HandshakeFailureTerminal(t *testing.T) {
	// Feed only a -ERR so the handshake fails.
	h := newHarness("-ERR no such mailbox\r\n")
	ctx := context.Background()

	_, err := h.store.List(ctx, "user@example.com")
	if err == nil {
		t.Fatal("expected error on first List after failed handshake")
	}

	// The buffer is now empty; a retry attempt would EOF. If it didn't get an
	// immediate error it would block or panic — the terminal check prevents that.
	_, err = h.store.List(ctx, "user@example.com")
	if err == nil {
		t.Fatal("expected error on second List after failed handshake")
	}
	// Auth pipe must have been closed exactly once (not twice).
	if !h.closed {
		t.Error("authPipeW.Close was not called")
	}
}

// TestSessionPipeStore_RetrievePartialReadDrainsOnClose verifies that Close()
// on the reader returned by Retrieve drains unread bytes so that subsequent
// pipe operations are not desynchronised.
func TestSessionPipeStore_RetrievePartialReadDrainsOnClose(t *testing.T) {
	body := "line1\r\nline2\r\nline3\r\n"
	h := newHarness(
		"+OK mailbox ready\r\n" +
			"+OK 0 0\r\n" + // LIST
			fmt.Sprintf("+DATA %d\r\n", len(body)) +
			body +
			"+OK deleted\r\n", // DELETE response after the partial read
	)
	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}

	rc, err := h.store.Retrieve(ctx, "user@example.com", "abc123")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}

	// Read only the first 5 bytes — deliberately leave the rest unread.
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatalf("partial read: %v", err)
	}

	// Close must drain the remaining bytes.
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The pipe should now be in sync: a DELETE should succeed.
	if err := h.store.Delete(ctx, "user@example.com", "abc123"); err != nil {
		t.Fatalf("Delete after partial retrieve: %v", err)
	}
}

// TestSessionPipeStore_ValidateUID verifies that UIDs containing whitespace are
// rejected before being written to the wire protocol.
func TestSessionPipeStore_ValidateUID(t *testing.T) {
	h := newHarness("+OK mailbox ready\r\n" + "+OK 0 0\r\n")
	ctx := context.Background()
	if _, err := h.store.List(ctx, "user@example.com"); err != nil {
		t.Fatalf("List: %v", err)
	}

	badUIDs := []string{"uid with space", "uid\nnewline", "uid\r\n", ""}
	for _, uid := range badUIDs {
		if err := h.store.Delete(ctx, "user@example.com", uid); err == nil {
			t.Errorf("Delete with uid %q: expected error, got nil", uid)
		}
		if _, err := h.store.Retrieve(ctx, "user@example.com", uid); err == nil {
			t.Errorf("Retrieve with uid %q: expected error, got nil", uid)
		}
	}
}

// TestSessionPipeStore_ValidateMailbox verifies that a mailbox containing
// newlines is rejected before being written to the wire protocol.
func TestSessionPipeStore_ValidateMailbox(t *testing.T) {
	h := newHarness("") // no responses needed — error before any write
	_, err := h.store.List(context.Background(), "user\r\nINJECTED@example.com")
	if err == nil {
		t.Error("expected error for mailbox with newline, got nil")
	}
}

// TestSessionPipeStore_ExpungeBeforeHandshake verifies that Expunge triggers
// the handshake when called before List.
func TestSessionPipeStore_ExpungeBeforeHandshake(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" + // MAILBOX (handshake)
			"+OK committed\r\n", // COMMIT
	)
	if err := h.store.Expunge(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if !h.closed {
		t.Error("authPipeW.Close was not called")
	}
}

// TestSessionPipeStore_StatBeforeHandshake verifies that Stat triggers the
// handshake when called before List.
func TestSessionPipeStore_StatBeforeHandshake(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" + // MAILBOX (handshake)
			"+OK 5 8192\r\n", // STAT
	)
	count, total, err := h.store.Stat(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 5 {
		t.Errorf("count: want 5, got %d", count)
	}
	if total != 8192 {
		t.Errorf("total: want 8192, got %d", total)
	}
	if !h.closed {
		t.Error("authPipeW.Close was not called")
	}
}

// TestSessionPipeStore_ListCountCap verifies that an absurdly large count from
// mail-session is rejected rather than causing an OOM allocation attempt.
func TestSessionPipeStore_ListCountCap(t *testing.T) {
	h := newHarness(
		"+OK mailbox ready\r\n" +
			fmt.Sprintf("+OK %d 0\r\n", maxListCount+1),
	)
	_, err := h.store.List(context.Background(), "user@example.com")
	if err == nil {
		t.Errorf("expected error for count > maxListCount, got nil")
	}
}
