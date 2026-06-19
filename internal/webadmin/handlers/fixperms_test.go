package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestDomainHandlerForFix(t *testing.T) (*DomainHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30*time.Minute, false)
	// roles nil -> RBAC disabled (treated as super_admin); Config==Data single tree.
	return NewDomainHandler(dir, dir, store, slog.Default(), nil, nil), dir
}

func fixPerms(t *testing.T, h *DomainHandler, domainName string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/domains/"+domainName+"/fix-perms", nil)
	req.SetPathValue("name", domainName)
	rr := httptest.NewRecorder()
	h.HandleFixPerms(rr, req)
	return rr
}

func TestFixPerms_RepairsDomain(t *testing.T) {
	h, dir := newTestDomainHandlerForFix(t)
	createTestDomain(t, dir, "example.com")

	rr := fixPerms(t, h, "example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp fixPermsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", resp.Domain)
	}
	if len(resp.Entries) == 0 {
		t.Error("expected at least the data + users dir entries")
	}
	// The shared dirs carry the setgid mode; confirm it rendered as 2750.
	foundSetgid := false
	for _, e := range resp.Entries {
		if e.Mode == "2750" {
			foundSetgid = true
		}
	}
	if !foundSetgid {
		t.Errorf("expected a 2750 (setgid) entry, got %+v", resp.Entries)
	}
}

func TestFixPerms_OffRootSkipsOwnership(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: ownership is applied, not skipped")
	}
	h, dir := newTestDomainHandlerForFix(t)
	createTestDomain(t, dir, "example.com")

	rr := fixPerms(t, h, "example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp fixPermsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.RunningAsRoot {
		t.Error("running_as_root should be false off-root")
	}
	if !resp.OwnershipSkipped {
		t.Error("ownership_skipped should be true off-root (chown requires root)")
	}
}

func TestFixPerms_DomainNotFound(t *testing.T) {
	h, _ := newTestDomainHandlerForFix(t)

	rr := fixPerms(t, h, "nonexistent.example")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestFixPerms_InvalidDomainName(t *testing.T) {
	h, _ := newTestDomainHandlerForFix(t)

	rr := fixPerms(t, h, "../etc")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUnixMode(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want string
	}{
		{os.FileMode(0o750) | os.ModeSetgid, "2750"},
		{os.FileMode(0o700), "0700"},
		{os.FileMode(0o640), "0640"},
	}
	for _, c := range cases {
		if got := unixMode(c.mode); got != c.want {
			t.Errorf("unixMode(%v) = %q, want %q", c.mode, got, c.want)
		}
	}
}
