package session_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/mail-session/session"
	"github.com/infodancer/maildancer/msgstore"
)

// mockStore implements msgstore.MessageStore for testing.
type mockStore struct {
	messages  map[string]string // uid -> body
	listOrder []string          // ordered UIDs
	deleted   []string          // UIDs passed to Delete
}

func newMockStore(msgs map[string]string, order []string) *mockStore {
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

func (m *mockStore) Retrieve(_ context.Context, _ string, uid string) (io.ReadCloser, error) {
	body, ok := m.messages[uid]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func (m *mockStore) Delete(_ context.Context, _ string, uid string) error {
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
		map[string]string{"uid1": "hello", "uid2": "world"},
		[]string{"uid1", "uid2"},
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
		map[string]string{"uid1": "hello", "uid2": "world"},
		[]string{"uid1", "uid2"},
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
		map[string]string{"uid1": "hello"},
		[]string{"uid1"},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete("uid1"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	// Second delete should fail.
	if err := s.Delete("uid1"); err == nil {
		t.Error("expected error on double-delete, got nil")
	}
}

func TestDeleteNotFound(t *testing.T) {
	store := newMockStore(map[string]string{}, []string{})
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete("nonexistent"); err == nil {
		t.Error("expected error for nonexistent UID, got nil")
	}
}

func TestUndelete(t *testing.T) {
	store := newMockStore(
		map[string]string{"uid1": "hello"},
		[]string{"uid1"},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete("uid1"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if err := s.Undelete("uid1"); err != nil {
		t.Fatalf("Undelete error: %v", err)
	}
	// Undelete again should fail.
	if err := s.Undelete("uid1"); err == nil {
		t.Error("expected error on double-undelete, got nil")
	}
}

func TestCommit(t *testing.T) {
	store := newMockStore(
		map[string]string{"uid1": "hello", "uid2": "world"},
		[]string{"uid1", "uid2"},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := s.Delete("uid1"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if err := s.Commit(context.Background()); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "uid1" {
		t.Errorf("store.deleted = %v, want [uid1]", store.deleted)
	}
}

func TestGetUID(t *testing.T) {
	store := newMockStore(
		map[string]string{"uid1": "hello"},
		[]string{"uid1"},
	)
	s := session.New(store)
	if err := s.Open(context.Background(), "testbox"); err != nil {
		t.Fatalf("Open error: %v", err)
	}
	info, err := s.GetUID("uid1")
	if err != nil {
		t.Fatalf("GetUID error: %v", err)
	}
	if info.UID != "uid1" {
		t.Errorf("UID = %q, want uid1", info.UID)
	}
	_, err = s.GetUID("missing")
	if err == nil {
		t.Error("expected error for missing UID, got nil")
	}
}
