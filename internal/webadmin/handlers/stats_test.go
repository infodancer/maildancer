package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// mockMessageStore implements msgstore.MessageStore for testing.
type mockMessageStore struct {
	count      int
	totalBytes int64
}

func (m *mockMessageStore) List(_ context.Context, _ string) ([]msgstore.MessageInfo, error) {
	return nil, nil
}
func (m *mockMessageStore) Retrieve(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockMessageStore) Delete(_ context.Context, _, _ string) error { return nil }
func (m *mockMessageStore) Expunge(_ context.Context, _ string) error   { return nil }
func (m *mockMessageStore) Stat(_ context.Context, _ string) (int, int64, error) {
	return m.count, m.totalBytes, nil
}

// mockMsgStore satisfies msgstore.MsgStore (DeliveryAgent + MessageStore)
type mockMsgStore struct {
	mockMessageStore
}

func (m *mockMsgStore) Deliver(_ context.Context, _ msgstore.Envelope, _ io.Reader) error {
	return nil
}

func newTestStatsHandler(t *testing.T, store msgstore.MessageStore) (*StatsHandler, string) {
	t.Helper()
	dir := t.TempDir()
	sessionStore := session.NewStore(30 * time.Minute, false)
	openStore := func(domainPath string) (msgstore.MessageStore, error) {
		return store, nil
	}
	return NewStatsHandler(dir, sessionStore, slog.Default(), openStore), dir
}

func TestHandleGetStats(t *testing.T) {
	store := &mockMsgStore{
		mockMessageStore: mockMessageStore{count: 42, totalBytes: 1024000},
	}
	h, dir := newTestStatsHandler(t, store)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/users/user1/stats", nil)
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleGetStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var stats MailboxStats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Username != "user1" {
		t.Errorf("expected username user1, got %s", stats.Username)
	}
	if stats.Count != 42 {
		t.Errorf("expected count 42, got %d", stats.Count)
	}
	if stats.TotalBytes != 1024000 {
		t.Errorf("expected totalBytes 1024000, got %d", stats.TotalBytes)
	}
}

func TestHandleGetStats_DomainNotFound(t *testing.T) {
	h, _ := newTestStatsHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/domains/missing.com/users/user1/stats", nil)
	req.SetPathValue("domain", "missing.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleGetStats(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetStats_UserNotFound(t *testing.T) {
	store := &mockMsgStore{}
	h, dir := newTestStatsHandler(t, store)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/users/missing/stats", nil)
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "missing")
	rr := httptest.NewRecorder()
	h.HandleGetStats(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetStats_InvalidInput(t *testing.T) {
	h, _ := newTestStatsHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/domains/../etc/users/user1/stats", nil)
	req.SetPathValue("domain", "../etc")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleGetStats(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
