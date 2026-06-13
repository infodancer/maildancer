package msgstore

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// searchMockStore is a MessageStore whose messages are addressable per UID,
// for exercising SearchContentStore.
type searchMockStore struct {
	msgs map[uint32][]byte // uid -> raw message
	keys []uint32          // listing order
}

func (m *searchMockStore) List(_ context.Context, _ string) ([]MessageInfo, error) {
	infos := make([]MessageInfo, 0, len(m.keys))
	for _, uid := range m.keys {
		infos = append(infos, MessageInfo{UID: uid, Size: int64(len(m.msgs[uid]))})
	}
	return infos, nil
}

func (m *searchMockStore) Retrieve(_ context.Context, _ string, uid uint32) (io.ReadCloser, error) {
	data, ok := m.msgs[uid]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *searchMockStore) Delete(_ context.Context, _ string, _ uint32) error { return nil }
func (m *searchMockStore) Expunge(_ context.Context, _ string) error          { return nil }
func (m *searchMockStore) Stat(_ context.Context, _ string) (int, int64, error) {
	return len(m.keys), 0, nil
}

const (
	msgAlice = "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: Lunch plans\r\n\r\nLet's meet at noon.\r\n"
	msgCarol = "From: Carol <carol@example.com>\r\nTo: bob@example.com\r\nSubject: Project update\r\n\r\nThe noon deploy is done.\r\n"
)

func newSearchStore() *searchMockStore {
	return &searchMockStore{
		msgs: map[uint32][]byte{1: []byte(msgAlice), 2: []byte(msgCarol)},
		keys: []uint32{1, 2},
	}
}

func TestSearchContentStore_BodyVsText(t *testing.T) {
	store := newSearchStore()

	// "lunch" appears only in Alice's Subject header, not in either body.
	// BODY must not match it (body-only); TEXT must (whole message).
	res, err := SearchContentStore(context.Background(), store, "INBOX", nil,
		[]string{"lunch"}, []string{"lunch"}, false)
	if err != nil {
		t.Fatalf("SearchContentStore: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	byUID := map[uint32]ContentMatch{res[0].UID: res[0], res[1].UID: res[1]}

	if byUID[1].BodyMatches[0] {
		t.Error("BODY lunch must not match a header-only term (body-only semantics)")
	}
	if !byUID[1].TextMatches[0] {
		t.Error("TEXT lunch must match (term is in the Subject header)")
	}
	if byUID[2].TextMatches[0] {
		t.Error("TEXT lunch must not match Carol's message")
	}
}

func TestSearchContentStore_BodyMatch(t *testing.T) {
	store := newSearchStore()

	// "noon" is in both bodies; case-insensitive.
	res, err := SearchContentStore(context.Background(), store, "INBOX", nil,
		[]string{"NOON"}, nil, false)
	if err != nil {
		t.Fatalf("SearchContentStore: %v", err)
	}
	for _, m := range res {
		if !m.BodyMatches[0] {
			t.Errorf("uid %d: BODY noon should match (case-insensitive)", m.UID)
		}
	}
}

func TestSearchContentStore_HeadersReturnedOnlyWhenRequested(t *testing.T) {
	store := newSearchStore()

	res, _ := SearchContentStore(context.Background(), store, "INBOX", []uint32{1}, nil, nil, false)
	if len(res) != 1 || res[0].Headers != nil {
		t.Errorf("headers must be nil when not requested, got %q", res[0].Headers)
	}

	res, _ = SearchContentStore(context.Background(), store, "INBOX", []uint32{1}, nil, nil, true)
	if len(res) != 1 || !bytes.Contains(res[0].Headers, []byte("Subject: Lunch plans")) {
		t.Errorf("headers must be returned when requested, got %q", res[0].Headers)
	}
	if bytes.Contains(res[0].Headers, []byte("Let's meet")) {
		t.Error("header block must not include the body")
	}
}

func TestSearchContentStore_UIDSubset(t *testing.T) {
	store := newSearchStore()
	res, err := SearchContentStore(context.Background(), store, "INBOX", []uint32{2}, []string{"noon"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].UID != 2 {
		t.Fatalf("want only uid 2, got %+v", res)
	}
}

func TestSplitMessage(t *testing.T) {
	h, b := splitMessage([]byte("A: 1\r\nB: 2\r\n\r\nbody here"))
	if string(h) != "A: 1\r\nB: 2\r\n\r\n" || string(b) != "body here" {
		t.Errorf("CRLF split wrong: h=%q b=%q", h, b)
	}
	h, b = splitMessage([]byte("A: 1\n\nbody"))
	if string(h) != "A: 1\n\n" || string(b) != "body" {
		t.Errorf("LF split wrong: h=%q b=%q", h, b)
	}
	h, b = splitMessage([]byte("A: 1\r\nB: 2\r\n"))
	if string(h) != "A: 1\r\nB: 2\r\n" || b != nil {
		t.Errorf("no-body split wrong: h=%q b=%q", h, b)
	}
}
