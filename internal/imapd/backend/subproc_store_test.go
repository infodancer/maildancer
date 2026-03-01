package backend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// fakeServer simulates a mail-session subprocess over a pipe pair.
type fakeServer struct {
	r *bufio.Reader
	w *bufio.Writer
}

func (f *fakeServer) readLine() string {
	line, _ := f.r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func (f *fakeServer) send(line string) {
	fmt.Fprintf(f.w, "%s\r\n", line)
	f.w.Flush()
}

func (f *fakeServer) sendLines(lines []string) {
	fmt.Fprintf(f.w, "+OK %d\r\n", len(lines))
	for _, l := range lines {
		fmt.Fprintf(f.w, "%s\r\n", l)
	}
	f.w.Flush()
}

// newTestStore creates a SubprocessStore backed by a goroutine running handler.
// handler is called after the MAILBOX handshake and should process expected commands.
// The goroutine exits when handler returns; t.Cleanup closes the pipes.
func newTestStore(t *testing.T, handler func(fs *fakeServer)) *SubprocessStore {
	t.Helper()
	sessionR, clientW := io.Pipe()
	clientR, sessionW := io.Pipe()

	t.Cleanup(func() {
		clientW.Close()
		clientR.Close()
	})

	go func() {
		defer sessionR.Close()
		defer sessionW.Close()
		fs := &fakeServer{
			r: bufio.NewReader(sessionR),
			w: bufio.NewWriter(sessionW),
		}
		fs.readLine() // consume MAILBOX command
		fs.send("+OK")
		handler(fs)
	}()

	store, err := newSubprocessStoreFromPipes(clientR, clientW, nil, "user@example.com")
	if err != nil {
		t.Fatalf("newSubprocessStoreFromPipes: %v", err)
	}
	return store
}

func TestSubprocStore_List(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "LIST" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.sendLines([]string{"uid1 100 \\Seen", "uid2 200"})
	})

	msgs, err := store.List(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].UID != "uid1" || msgs[0].Size != 100 {
		t.Errorf("msgs[0] = %+v, want uid1/100", msgs[0])
	}
	if len(msgs[0].Flags) != 1 || msgs[0].Flags[0] != `\Seen` {
		t.Errorf("msgs[0].Flags = %v, want [\\Seen]", msgs[0].Flags)
	}
	if msgs[1].UID != "uid2" || msgs[1].Size != 200 {
		t.Errorf("msgs[1] = %+v, want uid2/200", msgs[1])
	}
}

func TestSubprocStore_Retrieve(t *testing.T) {
	body := "From: test@example.com\r\nSubject: Test\r\n\r\nHello\r\n"
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "GET uid1" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fmt.Fprintf(fs.w, "+DATA %d\r\n", len(body))
		fmt.Fprint(fs.w, body)
		fs.w.Flush()
	})

	rc, err := store.Retrieve(context.Background(), "user@example.com", "uid1")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestSubprocStore_Delete(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		cmd := fs.readLine()
		if cmd != `SETFLAGS uid1 \Deleted` {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK")
	})

	if err := store.Delete(context.Background(), "user@example.com", "uid1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSubprocStore_Expunge(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "EXPUNGE" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.sendLines([]string{"uid1"})
	})

	if err := store.Expunge(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("Expunge: %v", err)
	}
}

func TestSubprocStore_Stat(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "STAT" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK 3 1500")
	})

	count, total, err := store.Stat(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 3 || total != 1500 {
		t.Errorf("Stat = (%d, %d), want (3, 1500)", count, total)
	}
}

func TestSubprocStore_ListFolders(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "FOLDERS" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.sendLines([]string{"Sent", "Drafts"})
	})

	folders, err := store.ListFolders(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(folders) != 2 || folders[0] != "Sent" || folders[1] != "Drafts" {
		t.Errorf("folders = %v, want [Sent Drafts]", folders)
	}
}

func TestSubprocStore_CreateFolder(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "CREATEFOLDER Sent" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK")
	})

	if err := store.CreateFolder(context.Background(), "user@example.com", "Sent"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
}

func TestSubprocStore_ListInFolder(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "SELECT Sent" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.sendLines([]string{"uid10 500 \\Seen"})
	})

	msgs, err := store.ListInFolder(context.Background(), "user@example.com", "Sent")
	if err != nil {
		t.Fatalf("ListInFolder: %v", err)
	}
	if len(msgs) != 1 || msgs[0].UID != "uid10" || msgs[0].Size != 500 {
		t.Errorf("msgs = %+v, want [{uid10 500 [\\Seen]}]", msgs)
	}
}

func TestSubprocStore_SetFlagsInFolder_INBOX(t *testing.T) {
	// On a fresh store, currentFolder is "" == INBOX, so ensureFolderLocked skips SELECT.
	store := newTestStore(t, func(fs *fakeServer) {
		cmd := fs.readLine()
		if cmd != `SETFLAGS uid1 \Seen` {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK")
	})

	err := store.SetFlagsInFolder(context.Background(), "user@example.com", "INBOX", "uid1", []string{`\Seen`})
	if err != nil {
		t.Fatalf("SetFlagsInFolder: %v", err)
	}
}

func TestSubprocStore_SetFlagsInFolder_SubFolder(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		// ensureFolderLocked("Sent") sends SELECT Sent
		if cmd := fs.readLine(); cmd != "SELECT Sent" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.sendLines(nil) // +OK 0 (empty folder)

		cmd := fs.readLine()
		if cmd != `SETFLAGS uid5 \Deleted` {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK")
	})

	err := store.SetFlagsInFolder(context.Background(), "user@example.com", "Sent", "uid5", []string{`\Deleted`})
	if err != nil {
		t.Fatalf("SetFlagsInFolder: %v", err)
	}
}

func TestSubprocStore_AppendToFolder(t *testing.T) {
	body := "From: test@example.com\r\n\r\nHello\r\n"
	store := newTestStore(t, func(fs *fakeServer) {
		line := fs.readLine()
		// Expect: APPEND INBOX <size> \Seen <date>
		if !strings.HasPrefix(line, fmt.Sprintf("APPEND INBOX %d ", len(body))) {
			fs.send("-ERR unexpected: " + line)
			return
		}
		// Read body bytes
		buf := make([]byte, len(body))
		io.ReadFull(fs.r, buf)
		fs.send("+OK newuid123")
	})

	uid, err := store.AppendToFolder(context.Background(), "user@example.com", "INBOX",
		strings.NewReader(body), []string{`\Seen`}, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if uid != "newuid123" {
		t.Errorf("uid = %q, want newuid123", uid)
	}
}

func TestSubprocStore_AppendToFolder_NoFlags(t *testing.T) {
	body := "Subject: Test\r\n\r\nBody\r\n"
	store := newTestStore(t, func(fs *fakeServer) {
		line := fs.readLine()
		if !strings.Contains(line, " NONE ") {
			fs.send("-ERR expected NONE flags: " + line)
			return
		}
		buf := make([]byte, len(body))
		io.ReadFull(fs.r, buf)
		fs.send("+OK uid999")
	})

	uid, err := store.AppendToFolder(context.Background(), "user@example.com", "INBOX",
		strings.NewReader(body), nil, time.Now())
	if err != nil {
		t.Fatalf("AppendToFolder: %v", err)
	}
	if uid != "uid999" {
		t.Errorf("uid = %q, want uid999", uid)
	}
}

func TestSubprocStore_CopyMessage(t *testing.T) {
	// Fresh store: currentFolder == "" == INBOX, so no SELECT for srcFolder=INBOX.
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "COPY uid1 Sent" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK newuid456")
	})

	newUID, err := store.CopyMessage(context.Background(), "user@example.com", "INBOX", "uid1", "Sent")
	if err != nil {
		t.Fatalf("CopyMessage: %v", err)
	}
	if newUID != "newuid456" {
		t.Errorf("newUID = %q, want newuid456", newUID)
	}
}

func TestSubprocStore_UIDValidity(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		if cmd := fs.readLine(); cmd != "UIDVALIDITY INBOX" {
			fs.send("-ERR unexpected: " + cmd)
			return
		}
		fs.send("+OK 12345")
	})

	v, err := store.UIDValidity(context.Background(), "user@example.com", "INBOX")
	if err != nil {
		t.Fatalf("UIDValidity: %v", err)
	}
	if v != 12345 {
		t.Errorf("UIDValidity = %d, want 12345", v)
	}
}

func TestSubprocStore_ErrorResponse(t *testing.T) {
	store := newTestStore(t, func(fs *fakeServer) {
		fs.readLine() // LIST
		fs.send("-ERR no mailbox selected")
	})

	_, err := store.List(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error on -ERR, got nil")
	}
	if !strings.Contains(err.Error(), "no mailbox selected") {
		t.Errorf("error = %q, want to contain 'no mailbox selected'", err)
	}
}

func TestSubprocStore_EnsureFolder_SelectsOnce(t *testing.T) {
	// Verify that two consecutive List calls on INBOX do not insert a SELECT
	// between them. If ensureFolderLocked incorrectly sends SELECT INBOX, the
	// fake server will return -ERR and List will fail.
	store := newTestStore(t, func(fs *fakeServer) {
		for range 2 {
			cmd := fs.readLine()
			if cmd != "LIST" {
				fs.send("-ERR expected LIST got: " + cmd)
				return
			}
			fs.sendLines(nil) // empty inbox
		}
	})

	for i := range 2 {
		if _, err := store.List(context.Background(), "user@example.com"); err != nil {
			t.Fatalf("List call %d: %v", i+1, err)
		}
	}
}
