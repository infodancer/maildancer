package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestForwardHandler(t *testing.T) (*ForwardHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30*time.Minute, false)
	return NewForwardHandler(dir, store, slog.Default(), nil), dir
}

// setForward issues a POST upsert and returns the recorder.
func setForward(t *testing.T, h *ForwardHandler, domainName, localpart, target string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(forwardSetRequest{Localpart: localpart, Target: target})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/"+domainName+"/forwards", bytes.NewReader(body))
	req.SetPathValue("name", domainName)
	rr := httptest.NewRecorder()
	h.HandleSetForward(rr, req)
	return rr
}

func listForwards(t *testing.T, h *ForwardHandler, domainName string) []forwardEntry {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/domains/"+domainName+"/forwards", nil)
	req.SetPathValue("name", domainName)
	rr := httptest.NewRecorder()
	h.HandleListForwards(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got []forwardEntry
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	return got
}

func TestForwards_SetAndList(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	if rr := setForward(t, h, "example.com", "sales", "alice@example.net"); rr.Code != http.StatusOK {
		t.Fatalf("set: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := listForwards(t, h, "example.com")
	if len(got) != 1 || got[0].Localpart != "sales" || got[0].Target != "alice@example.net" {
		t.Fatalf("want [sales -> alice@example.net], got %+v", got)
	}

	// The shared helper owns persistence; confirm the forwarding chain reads it.
	resolved, err := domain.ListDomainForwards(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if resolved["sales"] != "alice@example.net" {
		t.Fatalf("config.toml [forwards] not written as the chain reads it: %+v", resolved)
	}
}

func TestForwards_Catchall(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	if rr := setForward(t, h, "example.com", "*", "catchall@example.net"); rr.Code != http.StatusOK {
		t.Fatalf("set catchall: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	got := listForwards(t, h, "example.com")
	if len(got) != 1 || got[0].Localpart != "*" {
		t.Fatalf("want catchall entry, got %+v", got)
	}
}

func TestForwards_Edit(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	setForward(t, h, "example.com", "sales", "alice@example.net")
	if rr := setForward(t, h, "example.com", "sales", "bob@example.net"); rr.Code != http.StatusOK {
		t.Fatalf("edit: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	got := listForwards(t, h, "example.com")
	if len(got) != 1 || got[0].Target != "bob@example.net" {
		t.Fatalf("edit should upsert in place, got %+v", got)
	}
}

func TestForwards_MultiTargetRejected(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	rr := setForward(t, h, "example.com", "sales", "a@example.net, b@example.net")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("multi-target: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	// File must be unchanged: no entry was written.
	if got := listForwards(t, h, "example.com"); len(got) != 0 {
		t.Fatalf("rejected multi-target must not write; got %+v", got)
	}
}

func TestForwards_InvalidTargetRejected(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	rr := setForward(t, h, "example.com", "sales", "not-an-address")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid target: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestForwards_InvalidLocalpartRejected(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	rr := setForward(t, h, "example.com", "../escape", "alice@example.net")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid localpart: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestForwards_Delete(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")
	setForward(t, h, "example.com", "sales", "alice@example.net")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com/forwards/sales", nil)
	req.SetPathValue("name", "example.com")
	req.SetPathValue("localpart", "sales")
	rr := httptest.NewRecorder()
	h.HandleDeleteForward(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := listForwards(t, h, "example.com"); len(got) != 0 {
		t.Fatalf("entry should be gone, got %+v", got)
	}
}

func TestForwards_DeleteMissing(t *testing.T) {
	h, dir := newTestForwardHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com/forwards/ghost", nil)
	req.SetPathValue("name", "example.com")
	req.SetPathValue("localpart", "ghost")
	rr := httptest.NewRecorder()
	h.HandleDeleteForward(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete missing: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestForwards_DomainNotFound(t *testing.T) {
	h, _ := newTestForwardHandler(t)

	rr := setForward(t, h, "nonexistent.example", "sales", "alice@example.net")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing domain: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
