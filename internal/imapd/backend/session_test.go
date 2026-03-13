package backend

import (
	"context"
	"log/slog"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// newTestSession creates a Session wired to a mockStore and a no-op collector.
// It bypasses the NewSession constructor (which requires an imapserver.Conn)
// by directly populating fields.
func newTestSession(t *testing.T, store *mockStore) *Session {
	t.Helper()
	return &Session{
		store:       store,
		folderStore: store,
		mailbox:     "testuser@example.com",
		username:    "testuser@example.com",
		userDomain:  "example.com",
		collector:   &noopCollector{},
		logger:      slog.Default(),
	}
}

// noopCollector satisfies metrics.Collector for tests.
type noopCollector struct{}

func (n *noopCollector) ConnectionOpened()                {}
func (n *noopCollector) ConnectionClosed()                {}
func (n *noopCollector) TLSConnectionEstablished()        {}
func (n *noopCollector) AuthAttempt(_ string, _ bool)     {}
func (n *noopCollector) CommandProcessed(_ string)        {}
func (n *noopCollector) MessageFetched(_ string, _ int64) {}
func (n *noopCollector) MessageStored(_ string)           {}
func (n *noopCollector) MessageExpunged(_ string)         {}
func (n *noopCollector) FolderSelected(_ string)          {}

func TestHasFlag(t *testing.T) {
	flags := []string{"\\Seen", "\\Flagged"}
	if !hasFlag(flags, imap.FlagSeen) {
		t.Error("expected \\Seen to be present")
	}
	if hasFlag(flags, imap.FlagDeleted) {
		t.Error("expected \\Deleted to be absent")
	}
}

func TestApplyStoreFlagsSet(t *testing.T) {
	current := []string{"\\Seen"}
	result := applyStoreFlagsStr(current, &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagFlagged, imap.FlagDeleted},
	})
	if len(result) != 2 {
		t.Fatalf("expected 2 flags, got %d", len(result))
	}
}

func TestApplyStoreFlagsAdd(t *testing.T) {
	current := []string{"\\Seen"}
	result := applyStoreFlagsStr(current, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	})
	if len(result) != 2 {
		t.Fatalf("expected 2 flags, got %d", len(result))
	}
	if !hasFlag(result, imap.FlagSeen) || !hasFlag(result, imap.FlagFlagged) {
		t.Error("missing expected flags")
	}
}

func TestApplyStoreFlagsDel(t *testing.T) {
	current := []string{"\\Seen", "\\Flagged"}
	result := applyStoreFlagsStr(current, &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagSeen},
	})
	if len(result) != 1 || result[0] != "\\Flagged" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestIsValidMailboxName(t *testing.T) {
	valid := []string{"INBOX", "Sent", "Trash", "My.Folder"}
	for _, name := range valid {
		if !isValidMailboxName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	invalid := []string{"", "../etc/passwd", "foo/bar", ".."}
	for _, name := range invalid {
		if isValidMailboxName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestSelect_INBOX(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", []string{"\\Seen"}, "From: a@b.com\r\n\r\nHello")
	store.addInboxMessage("testuser@example.com", nil, "From: c@d.com\r\n\r\nWorld")

	s := newTestSession(t, store)
	data, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	if data.NumMessages != 2 {
		t.Errorf("expected 2 messages, got %d", data.NumMessages)
	}
	// First unseen should be msg 2 (index 1, seqnum 2)
	if data.FirstUnseenSeqNum != 2 {
		t.Errorf("expected FirstUnseenSeqNum=2, got %d", data.FirstUnseenSeqNum)
	}
}

func TestSelect_Folder(t *testing.T) {
	store := newMockStore()
	_ = store.CreateFolder(context.Background(), "testuser@example.com", "Sent")
	store.addFolderMessage("testuser@example.com", "Sent", []string{"\\Seen"}, "From: a@b.com\r\n\r\nSent message")

	s := newTestSession(t, store)
	data, err := s.Select("Sent", nil)
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	if data.NumMessages != 1 {
		t.Errorf("expected 1 message, got %d", data.NumMessages)
	}
}

func TestStatus_NumMessages(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "msg1")
	store.addInboxMessage("testuser@example.com", []string{"\\Seen"}, "msg2")

	s := newTestSession(t, store)
	data, err := s.Status("INBOX", &imap.StatusOptions{NumMessages: true, NumUnseen: true})
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if data.NumMessages == nil || *data.NumMessages != 2 {
		t.Errorf("expected NumMessages=2")
	}
	if data.NumUnseen == nil || *data.NumUnseen != 1 {
		t.Errorf("expected NumUnseen=1, got %v", data.NumUnseen)
	}
}

func TestCreate_Delete_Folder(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)

	if err := s.Create("Archive", nil); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify folder was created via the store
	folders, err := store.ListFolders(context.Background(), "testuser@example.com")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range folders {
		if f == "Archive" {
			found = true
		}
	}
	if !found {
		t.Error("Archive not found after Create")
	}

	if err := s.Delete("Archive"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

func TestCreate_INBOX_Fails(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	if err := s.Create("INBOX", nil); err == nil {
		t.Error("expected error creating INBOX")
	}
}

func TestDelete_INBOX_Fails(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	if err := s.Delete("INBOX"); err == nil {
		t.Error("expected error deleting INBOX")
	}
}

func TestRename_Folder(t *testing.T) {
	store := newMockStore()
	_ = store.CreateFolder(context.Background(), "testuser@example.com", "OldName")

	s := newTestSession(t, store)
	if err := s.Rename("OldName", "NewName", nil); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	folders, err := store.ListFolders(context.Background(), "testuser@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range folders {
		if f == "OldName" {
			t.Error("OldName still exists after rename")
		}
	}
}

func TestRename_INBOX_Fails(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	if err := s.Rename("INBOX", "Other", nil); err == nil {
		t.Error("expected error renaming INBOX")
	}
}

func TestSearch_ByFlag(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", []string{"\\Seen"}, "seen message")
	store.addInboxMessage("testuser@example.com", nil, "unseen message")

	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Search for unseen messages
	criteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}
	result, err := s.Search(imapserver.NumKindSeq, criteria, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	nums, ok := result.All.(imap.SeqSet)
	if !ok {
		t.Fatal("expected SeqSet result")
	}
	seqNums, _ := nums.Nums()
	if len(seqNums) != 1 || seqNums[0] != 2 {
		t.Errorf("expected seqnum 2, got %v", seqNums)
	}
}

func TestSearch_ByFlagUID(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", []string{"\\Seen"}, "seen message")
	store.addInboxMessage("testuser@example.com", nil, "unseen message")

	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}

	criteria := &imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}
	result, err := s.Search(imapserver.NumKindUID, criteria, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	uids, ok := result.All.(imap.UIDSet)
	if !ok {
		t.Fatal("expected UIDSet result")
	}
	nums, _ := uids.Nums()
	if len(nums) != 1 || nums[0] != 1 {
		t.Errorf("expected uid 1, got %v", nums)
	}
}

func TestResolveNumSet_UIDDynamicRange(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", []string{"\\Seen"}, "msg1")
	store.addInboxMessage("testuser@example.com", nil, "msg2")
	store.addInboxMessage("testuser@example.com", nil, "msg3")
	store.addInboxMessage("testuser@example.com", nil, "msg4")
	store.addInboxMessage("testuser@example.com", nil, "msg5")

	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("UID 6:* with 5 messages returns only last message", func(t *testing.T) {
		// Simulates Thunderbird's new-mail check: UID FETCH <uidnext>:* (FLAGS)
		// When uidnext=6 and max UID=5, should return only UID 5 per RFC 9051.
		var uidSet imap.UIDSet
		uidSet.AddRange(6, 0) // 6:* (0 represents *)
		indices := s.resolveNumSet(uidSet)
		if len(indices) != 1 {
			t.Fatalf("expected 1 index (last message), got %d: %v", len(indices), indices)
		}
		if indices[0] != 4 {
			t.Errorf("expected index 4 (last message), got %d", indices[0])
		}
	})

	t.Run("UID 3:* returns UIDs 3-5", func(t *testing.T) {
		var uidSet imap.UIDSet
		uidSet.AddRange(3, 0) // 3:*
		indices := s.resolveNumSet(uidSet)
		if len(indices) != 3 {
			t.Fatalf("expected 3 indices, got %d: %v", len(indices), indices)
		}
		// Should be indices 2, 3, 4 (UIDs 3, 4, 5)
		for i, want := range []int{2, 3, 4} {
			if indices[i] != want {
				t.Errorf("indices[%d] = %d, want %d", i, indices[i], want)
			}
		}
	})

	t.Run("UID * returns only last message", func(t *testing.T) {
		var uidSet imap.UIDSet
		uidSet.AddNum(0) // bare *
		indices := s.resolveNumSet(uidSet)
		if len(indices) != 1 {
			t.Fatalf("expected 1 index, got %d: %v", len(indices), indices)
		}
		if indices[0] != 4 {
			t.Errorf("expected index 4, got %d", indices[0])
		}
	})

	t.Run("UID 1:* returns all messages", func(t *testing.T) {
		var uidSet imap.UIDSet
		uidSet.AddRange(1, 0) // 1:*
		indices := s.resolveNumSet(uidSet)
		if len(indices) != 5 {
			t.Fatalf("expected 5 indices, got %d: %v", len(indices), indices)
		}
	})

	t.Run("static UID set still works", func(t *testing.T) {
		var uidSet imap.UIDSet
		uidSet.AddNum(2)
		uidSet.AddNum(4)
		indices := s.resolveNumSet(uidSet)
		if len(indices) != 2 {
			t.Fatalf("expected 2 indices, got %d: %v", len(indices), indices)
		}
		if indices[0] != 1 || indices[1] != 3 {
			t.Errorf("expected [1, 3], got %v", indices)
		}
	})
}

func TestResolveNumSet_SeqDynamicRange(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "msg1")
	store.addInboxMessage("testuser@example.com", nil, "msg2")
	store.addInboxMessage("testuser@example.com", nil, "msg3")

	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("seq * returns last message", func(t *testing.T) {
		var seqSet imap.SeqSet
		seqSet.AddNum(0) // bare *
		indices := s.resolveNumSet(seqSet)
		if len(indices) != 1 {
			t.Fatalf("expected 1 index, got %d: %v", len(indices), indices)
		}
		if indices[0] != 2 {
			t.Errorf("expected index 2 (last), got %d", indices[0])
		}
	})

	t.Run("seq 2:* returns messages 2-3", func(t *testing.T) {
		var seqSet imap.SeqSet
		seqSet.AddRange(2, 0) // 2:*
		indices := s.resolveNumSet(seqSet)
		if len(indices) != 2 {
			t.Fatalf("expected 2 indices, got %d: %v", len(indices), indices)
		}
		if indices[0] != 1 || indices[1] != 2 {
			t.Errorf("expected [1, 2], got %v", indices)
		}
	})
}

func TestResolveNumSet_EmptyMailbox(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}

	var uidSet imap.UIDSet
	uidSet.AddRange(1, 0) // 1:*
	indices := s.resolveNumSet(uidSet)
	if len(indices) != 0 {
		t.Errorf("expected 0 indices for empty mailbox, got %d", len(indices))
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"user", "local"},
		{"user@", ""},
	}
	for _, tt := range tests {
		got := extractDomain(tt.input)
		if got != tt.want {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestListMessages_INBOX(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "msg1")

	s := newTestSession(t, store)
	msgs, err := s.listMessages(context.Background(), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message, got %d", len(msgs))
	}
}

func TestListMessages_Folder(t *testing.T) {
	store := newMockStore()
	_ = store.CreateFolder(context.Background(), "testuser@example.com", "Sent")
	store.addFolderMessage("testuser@example.com", "Sent", nil, "msg1")

	s := newTestSession(t, store)
	msgs, err := s.listMessages(context.Background(), "Sent")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message, got %d", len(msgs))
	}
}

func TestRetrieveMessage_INBOX(t *testing.T) {
	store := newMockStore()
	info := store.addInboxMessage("testuser@example.com", nil, "test body content")

	s := newTestSession(t, store)
	rc, err := s.retrieveMessage(context.Background(), "INBOX", info.UID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	buf := make([]byte, 1024)
	n, _ := rc.Read(buf)
	if string(buf[:n]) != "test body content" {
		t.Errorf("unexpected content: %q", string(buf[:n]))
	}
}

func TestGetUIDValidity(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)

	v := s.getUIDValidity(context.Background(), "INBOX")
	if v != 12345 {
		t.Errorf("expected UIDValidity 12345, got %d", v)
	}
}

func TestUnselect(t *testing.T) {
	store := newMockStore()
	store.addInboxMessage("testuser@example.com", nil, "msg1")

	s := newTestSession(t, store)
	_, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.selectedMailbox != "INBOX" {
		t.Error("expected INBOX to be selected")
	}

	_ = s.Unselect()
	if s.selectedMailbox != "" {
		t.Error("expected no mailbox selected after Unselect")
	}
	if s.messages != nil {
		t.Error("expected messages to be nil after Unselect")
	}
}

func TestClose(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	// Close should not panic even when no mailbox is selected
	if err := s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestSubscribe_Unsubscribe(t *testing.T) {
	store := newMockStore()
	s := newTestSession(t, store)
	if err := s.Subscribe("INBOX"); err != nil {
		t.Errorf("Subscribe failed: %v", err)
	}
	if err := s.Unsubscribe("INBOX"); err != nil {
		t.Errorf("Unsubscribe failed: %v", err)
	}
}
