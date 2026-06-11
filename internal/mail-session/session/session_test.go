package session_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
)

// mockStore implements msgstore.MessageStore for testing.
type mockStore struct {
	messages  map[uint32]string // uid -> body
	listOrder []uint32          // ordered UIDs
	deleted   []uint32          // UIDs passed to Delete
}

func newMockStore(msgs map[uint32]string, order []uint32) *mockStore {
	return &mockStore{messages: msgs, listOrder: order}
}

func (m *mockStore) List(_ context.Context, _ string) ([]msgstore.MessageInfo, error) {
	infos := make([]msgstore.MessageInfo, 0, len(m.listOrder))
	for _, uid := range m.listOrder {
		body := m.messages[uid]
		infos = append(infos, msgstore.MessageInfo{
			UID:          uid,
			Size:         int64(len(body)),
			Flags:        []string{},
			InternalDate: time.Now(),
		})
	}
	return infos, nil
}

func (m *mockStore) Retrieve(_ context.Context, _ string, uid uint32) (io.ReadCloser, error) {
	body, ok := m.messages[uid]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func (m *mockStore) Delete(_ context.Context, _ string, uid uint32) error {
	m.deleted = append(m.deleted, uid)
	return nil
}

func (m *mockStore) Expunge(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) Stat(_ context.Context, _ string) (int, int64, error) {
	var total int64
	for _, body := range m.messages {
		total += int64(len(body))
	}
	return len(m.messages), total, nil
}

func TestOpen(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello", 2: "world"},
		[]uint32{1, 2},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	infos := s.List()
	if len(infos) != 2 {
		t.Fatalf("List len = %d, want 2", len(infos))
	}
}

func TestStat(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello", 2: "world"},
		[]uint32{1, 2},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	count, total := s.Stat()
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if total != 10 { // "hello"=5 + "world"=5
		t.Errorf("total = %d, want 10", total)
	}
}

func TestDelete(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete(1); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	// Second delete should fail.
	if err := s.Delete(1); err == nil {
		t.Error("expected error on double-delete, got nil")
	}
}

func TestDeleteNotFound(t *testing.T) {
	store := newMockStore(map[uint32]string{}, []uint32{})
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete(999); err == nil {
		t.Error("expected error for nonexistent UID, got nil")
	}
}

func TestUndelete(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete(1); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if err := s.Undelete(1); err != nil {
		t.Fatalf("Undelete error: %v", err)
	}
	// Undelete again should fail.
	if err := s.Undelete(1); err == nil {
		t.Error("expected error on double-undelete, got nil")
	}
}

func TestCommit(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello", 2: "world"},
		[]uint32{1, 2},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete(1); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if err := s.Commit(context.Background()); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	if len(store.deleted) != 1 || store.deleted[0] != 1 {
		t.Errorf("store.deleted = %v, want [1]", store.deleted)
	}
}

func TestGetUID(t *testing.T) {
	store := newMockStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	info, err := s.GetUID(1)
	if err != nil {
		t.Fatalf("GetUID error: %v", err)
	}
	if info.UID != 1 {
		t.Errorf("UID = %d, want 1", info.UID)
	}
	_, err = s.GetUID(999)
	if err == nil {
		t.Error("expected error for missing UID, got nil")
	}
}

// ── IMAP-path tests ───────────────────────────────────────────────────────────

// mockFullStore implements both msgstore.MessageStore and msgstore.FolderStore.
type mockFullStore struct {
	*mockStore

	// FolderStore state
	folders      []string
	folderMsgs   map[string][]msgstore.MessageInfo // folder -> message list
	folderBodies map[string]map[uint32]string      // folder -> uid -> body

	// Recorded calls
	createdFolders  []string
	deletedFolders  []string
	renamedFolders  [][2]string
	expungedFolders []string
	flagsSet        map[uint32][]string // uid -> latest flags
	appendedCount   int
	copiedCount     int
	lastAppendUID   uint32
	lastCopyUID     uint32
	nextUID         uint32 // counter for generating UIDs
}

func newMockFullStore(msgs map[uint32]string, order []uint32) *mockFullStore {
	return &mockFullStore{
		mockStore:    newMockStore(msgs, order),
		folderMsgs:   make(map[string][]msgstore.MessageInfo),
		folderBodies: make(map[string]map[uint32]string),
		flagsSet:     make(map[uint32][]string),
		nextUID:      100, // start at 100 to distinguish from INBOX UIDs
	}
}

func (m *mockFullStore) CreateFolder(_ context.Context, _, folder string) error {
	m.createdFolders = append(m.createdFolders, folder)
	m.folders = append(m.folders, folder)
	return nil
}

func (m *mockFullStore) ListFolders(_ context.Context, _ string) ([]string, error) {
	return m.folders, nil
}

func (m *mockFullStore) DeleteFolder(_ context.Context, _, folder string) error {
	m.deletedFolders = append(m.deletedFolders, "folder:"+folder)
	return nil
}

func (m *mockFullStore) ListInFolder(_ context.Context, _, folder string) ([]msgstore.MessageInfo, error) {
	return m.folderMsgs[folder], nil
}

func (m *mockFullStore) StatFolder(_ context.Context, _, folder string) (int, int64, error) {
	msgs := m.folderMsgs[folder]
	var total int64
	for _, msg := range msgs {
		total += msg.Size
	}
	return len(msgs), total, nil
}

func (m *mockFullStore) RetrieveFromFolder(_ context.Context, _, folder string, uid uint32) (io.ReadCloser, error) {
	bodies := m.folderBodies[folder]
	if bodies == nil {
		return nil, io.ErrUnexpectedEOF
	}
	body, ok := bodies[uid]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func (m *mockFullStore) DeleteInFolder(_ context.Context, _, folder string, uid uint32) error {
	m.deleted = append(m.deleted, uid)
	m.deletedFolders = append(m.deletedFolders, fmt.Sprintf("msg:%s/%d", folder, uid))
	return nil
}

func (m *mockFullStore) ExpungeFolder(_ context.Context, _, folder string) error {
	m.expungedFolders = append(m.expungedFolders, folder)
	// Remove messages with \Deleted flag from the in-memory list.
	var kept []msgstore.MessageInfo
	for _, msg := range m.folderMsgs[folder] {
		if !hasDeletedFlag(msg.Flags) {
			kept = append(kept, msg)
		}
	}
	m.folderMsgs[folder] = kept
	return nil
}

func (m *mockFullStore) DeliverToFolder(_ context.Context, _, _ string, _ io.Reader) error {
	return nil
}

func (m *mockFullStore) RenameFolder(_ context.Context, _, oldName, newName string) error {
	m.renamedFolders = append(m.renamedFolders, [2]string{oldName, newName})
	return nil
}

func (m *mockFullStore) AppendToFolder(_ context.Context, _, folder string, r io.Reader, flags []string, _ time.Time) (uint32, error) {
	m.appendedCount++
	m.nextUID++
	uid := m.nextUID
	m.lastAppendUID = uid
	body, _ := io.ReadAll(r)
	if m.folderBodies[folder] == nil {
		m.folderBodies[folder] = make(map[uint32]string)
	}
	m.folderBodies[folder][uid] = string(body)
	m.folderMsgs[folder] = append(m.folderMsgs[folder], msgstore.MessageInfo{
		UID:   uid,
		Size:  int64(len(body)),
		Flags: flags,
	})
	return uid, nil
}

func (m *mockFullStore) SetFlagsInFolder(_ context.Context, _, _ string, uid uint32, flags []string) error {
	m.flagsSet[uid] = flags
	return nil
}

func (m *mockFullStore) CopyMessage(_ context.Context, _, _ string, uid uint32, destFolder string) (uint32, error) {
	m.copiedCount++
	m.nextUID++
	newUID := m.nextUID
	m.lastCopyUID = newUID
	_ = destFolder
	return newUID, nil
}

func (m *mockFullStore) UIDValidity(_ context.Context, _, _ string) (uint32, error) {
	return 42, nil
}

func (m *mockFullStore) UIDNext(_ context.Context, _, _ string) (uint32, error) {
	return m.nextUID + 1, nil
}

// hasDeletedFlag is a local helper (mirrors session's internal hasFlag).
func hasDeletedFlag(flags []string) bool {
	for _, f := range flags {
		if f == `\Deleted` {
			return true
		}
	}
	return false
}

func openSession(t *testing.T, store msgstore.MessageStore) *session.Session {
	t.Helper()
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestSelect_INBOX(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)
	msgs, err := s.Select(context.Background(), "INBOX")
	if err != nil {
		t.Fatalf("Select INBOX: %v", err)
	}
	if len(msgs) != 1 || msgs[0].UID != 1 {
		t.Errorf("msgs = %v, want [{UID:1 ...}]", msgs)
	}
}

func TestSelect_CustomFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	store.folderMsgs["Sent"] = []msgstore.MessageInfo{
		{UID: 10, Size: 10, Flags: []string{}},
	}
	s := openSession(t, store)
	msgs, err := s.Select(context.Background(), "Sent")
	if err != nil {
		t.Fatalf("Select Sent: %v", err)
	}
	if len(msgs) != 1 || msgs[0].UID != 10 {
		t.Errorf("msgs = %v, want [{UID:10 ...}]", msgs)
	}
}

func TestFolders(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	store.folders = []string{"Sent", "Drafts"}
	s := openSession(t, store)
	folders, err := s.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if len(folders) != 2 {
		t.Errorf("len(folders) = %d, want 2", len(folders))
	}
}

func TestUIDValidity(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	s := openSession(t, store)
	v, err := s.UIDValidity(context.Background(), "INBOX")
	if err != nil {
		t.Fatalf("UIDValidity: %v", err)
	}
	if v != 42 {
		t.Errorf("UIDValidity = %d, want 42", v)
	}
}

func TestCreateFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	s := openSession(t, store)
	if err := s.CreateFolder(context.Background(), "Archive"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if len(store.createdFolders) != 1 || store.createdFolders[0] != "Archive" {
		t.Errorf("createdFolders = %v, want [Archive]", store.createdFolders)
	}
}

func TestDeleteFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	store.folders = []string{"Trash"}
	s := openSession(t, store)
	if err := s.DeleteFolder(context.Background(), "Trash"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if len(store.deletedFolders) != 1 || store.deletedFolders[0] != "folder:Trash" {
		t.Errorf("deletedFolders = %v, want [folder:Trash]", store.deletedFolders)
	}
}

func TestRenameFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	s := openSession(t, store)
	if err := s.RenameFolder(context.Background(), "Old", "New"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	if len(store.renamedFolders) != 1 || store.renamedFolders[0] != [2]string{"Old", "New"} {
		t.Errorf("renamedFolders = %v, want [[Old New]]", store.renamedFolders)
	}
}

func TestSetFlags_UpdatesCache(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)
	newFlags := []string{`\Seen`, `\Flagged`}
	if err := s.SetFlags(context.Background(), 1, newFlags); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	// Verify the store received the call.
	if got := store.flagsSet[1]; len(got) != 2 {
		t.Errorf("flagsSet[1] = %v, want %v", got, newFlags)
	}
	// Verify in-memory cache was updated.
	info, err := s.GetUID(1)
	if err != nil {
		t.Fatalf("GetUID: %v", err)
	}
	if len(info.Flags) != 2 || info.Flags[0] != `\Seen` {
		t.Errorf("cached flags = %v, want %v", info.Flags, newFlags)
	}
}

func TestExpunge_DeletesMarkedMessages(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello", 2: "world"},
		[]uint32{1, 2},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Mark uid 1 deleted in cache via SetFlags (INBOX path).
	if err := s.SetFlags(context.Background(), 1, []string{`\Deleted`}); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	expelled, err := s.Expunge(context.Background())
	if err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if len(expelled) != 1 || expelled[0] != 1 {
		t.Errorf("expelled = %v, want [1]", expelled)
	}
}

func TestAppendMessage(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	s := openSession(t, store)
	uid, err := s.AppendMessage(context.Background(), "Sent", []byte("body"), []string{`\Seen`}, time.Now())
	if err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if uid == 0 {
		t.Error("AppendMessage returned zero UID")
	}
	if store.appendedCount != 1 {
		t.Errorf("appendedCount = %d, want 1", store.appendedCount)
	}
}

func TestCopyMessage(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)
	newUID, err := s.CopyMessage(context.Background(), 1, "Archive")
	if err != nil {
		t.Fatalf("CopyMessage: %v", err)
	}
	if newUID == 0 {
		t.Error("CopyMessage returned zero UID")
	}
	if store.copiedCount != 1 {
		t.Errorf("copiedCount = %d, want 1", store.copiedCount)
	}
}

func TestMoveMessage_FolderToFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	// Seed Sent with a message.
	store.folderBodies["Sent"] = map[uint32]string{10: "msg body"}
	store.folderMsgs["Sent"] = []msgstore.MessageInfo{{UID: 10, Size: 8}}

	s := openSession(t, store)
	newUID, err := s.MoveMessage(context.Background(), 10, "Sent", "Archive")
	if err != nil {
		t.Fatalf("MoveMessage: %v", err)
	}
	if newUID == 0 {
		t.Error("MoveMessage returned zero UID")
	}
	// Copy must have been called.
	if store.copiedCount != 1 {
		t.Errorf("copiedCount = %d, want 1", store.copiedCount)
	}
	// DeleteInFolder must have been called -- check that UID 10 was deleted.
	found := false
	for _, uid := range store.deleted {
		if uid == 10 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deleted = %v, want to contain 10", store.deleted)
	}
	// ExpungeFolder must have been called for Sent.
	if len(store.expungedFolders) != 1 || store.expungedFolders[0] != "Sent" {
		t.Errorf("expungedFolders = %v, want [Sent]", store.expungedFolders)
	}
}

func TestMoveMessage_InboxToFolder(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "inbox message"},
		[]uint32{1},
	)
	s := openSession(t, store)
	newUID, err := s.MoveMessage(context.Background(), 1, "INBOX", "Junk")
	if err != nil {
		t.Fatalf("MoveMessage INBOX->Junk: %v", err)
	}
	if newUID == 0 {
		t.Error("returned zero UID")
	}
	// INBOX path: store.Delete (not DeleteInFolder) must be called.
	if len(store.deleted) != 1 || store.deleted[0] != 1 {
		t.Errorf("store.deleted = %v, want [1]", store.deleted)
	}
}

// ── Rescan tests ─────────────────────────────────────────────────────────────

func TestRescan_NoMailbox(t *testing.T) {
	store := newMockStore(map[uint32]string{}, []uint32{})
	s := session.New(store)
	_, err := s.Rescan(context.Background())
	if err == nil {
		t.Fatal("expected error for rescan without open mailbox")
	}
}

func TestRescan_NoNewMessages(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)
	if _, err := s.Select(context.Background(), "INBOX"); err != nil {
		t.Fatalf("Select: %v", err)
	}
	newMsgs, err := s.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if len(newMsgs) != 0 {
		t.Errorf("expected 0 new messages, got %d", len(newMsgs))
	}
}

func TestRescan_DetectsNewMessages(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)
	if _, err := s.Select(context.Background(), "INBOX"); err != nil {
		t.Fatalf("Select: %v", err)
	}

	// Simulate a new message arriving in the store.
	store.messages[2] = "world"
	store.listOrder = []uint32{1, 2}

	newMsgs, err := s.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if len(newMsgs) != 1 {
		t.Fatalf("expected 1 new message, got %d", len(newMsgs))
	}
	if newMsgs[0].UID != 2 {
		t.Errorf("new message UID = %d, want 2", newMsgs[0].UID)
	}

	// Second rescan with no further changes should return 0.
	newMsgs2, err := s.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan 2: %v", err)
	}
	if len(newMsgs2) != 0 {
		t.Errorf("expected 0 new messages on second rescan, got %d", len(newMsgs2))
	}
}

func TestRescan_CustomFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	store.folderMsgs["Sent"] = []msgstore.MessageInfo{
		{UID: 10, Size: 10, Flags: []string{}},
	}
	s := openSession(t, store)
	if _, err := s.Select(context.Background(), "Sent"); err != nil {
		t.Fatalf("Select Sent: %v", err)
	}

	// Add a new message to the Sent folder.
	store.folderMsgs["Sent"] = append(store.folderMsgs["Sent"],
		msgstore.MessageInfo{UID: 11, Size: 20, Flags: []string{}},
	)

	newMsgs, err := s.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if len(newMsgs) != 1 || newMsgs[0].UID != 11 {
		t.Errorf("newMsgs = %v, want [{UID:11 ...}]", newMsgs)
	}
}

func TestRescan_AfterOpen_INBOX(t *testing.T) {
	// Rescan should work on INBOX even without an explicit SELECT,
	// as long as the mailbox is open (POP3 path).
	store := newMockFullStore(
		map[uint32]string{1: "hello"},
		[]uint32{1},
	)
	s := openSession(t, store)

	store.messages[2] = "world"
	store.listOrder = []uint32{1, 2}

	newMsgs, err := s.Rescan(context.Background())
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if len(newMsgs) != 1 || newMsgs[0].UID != 2 {
		t.Errorf("newMsgs = %v, want [{UID:2 ...}]", newMsgs)
	}
}

func TestSelectedFolder(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	store.folderMsgs["Sent"] = []msgstore.MessageInfo{}
	s := openSession(t, store)
	if got := s.SelectedFolder(); got != "" {
		t.Errorf("SelectedFolder before Select = %q, want empty", got)
	}
	if _, err := s.Select(context.Background(), "Sent"); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := s.SelectedFolder(); got != "Sent" {
		t.Errorf("SelectedFolder after Select = %q, want Sent", got)
	}
}

func TestMoveMessage_SameFolder_Error(t *testing.T) {
	store := newMockFullStore(map[uint32]string{}, []uint32{})
	s := openSession(t, store)
	_, err := s.MoveMessage(context.Background(), 1, "Junk", "Junk")
	if err == nil {
		t.Fatal("expected error for same-folder move, got nil")
	}
}

func TestMoveMessage_EmptySrcTreatedAsINBOX(t *testing.T) {
	store := newMockFullStore(
		map[uint32]string{1: "msg"},
		[]uint32{1},
	)
	s := openSession(t, store)
	// Empty srcFolder should be treated as INBOX, not fail.
	_, err := s.MoveMessage(context.Background(), 1, "", "Sent")
	if err != nil {
		t.Fatalf("MoveMessage with empty src: %v", err)
	}
	// INBOX path: store.deleted should contain 1 (via store.Delete, not DeleteInFolder).
	if len(store.deleted) != 1 || store.deleted[0] != 1 {
		t.Errorf("store.deleted = %v, want [1]", store.deleted)
	}
}
