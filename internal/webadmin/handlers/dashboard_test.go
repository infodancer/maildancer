package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestDashboardHandler(t *testing.T) (*DashboardHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30 * time.Minute, false)
	return NewDashboardHandler(dir, store, slog.Default()), dir
}

func TestHandleGetDashboard_Empty(t *testing.T) {
	h, _ := newTestDashboardHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	rr := httptest.NewRecorder()
	h.HandleGetDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var stats DashboardStats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.DomainCount != 0 {
		t.Errorf("expected 0 domains, got %d", stats.DomainCount)
	}
	if stats.TotalUsers != 0 {
		t.Errorf("expected 0 total users, got %d", stats.TotalUsers)
	}
	if len(stats.ByDomain) != 0 {
		t.Errorf("expected empty by_domain, got %d entries", len(stats.ByDomain))
	}
}

func TestHandleGetDashboard_WithDomains(t *testing.T) {
	h, dir := newTestDashboardHandler(t)

	// Domain 1: 2 users, 1 pub key.
	createDashboardTestDomain(t, dir, "example.com", "user1:hash:u1\nuser2:hash:u2\n", true)
	// Domain 2: 1 user, no pub keys.
	createDashboardTestDomain(t, dir, "other.org", "user3:hash:u3\n", false)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	rr := httptest.NewRecorder()
	h.HandleGetDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var stats DashboardStats
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}

	if stats.DomainCount != 2 {
		t.Errorf("expected domain_count 2, got %d", stats.DomainCount)
	}
	if stats.TotalUsers != 3 {
		t.Errorf("expected total_users 3, got %d", stats.TotalUsers)
	}
	if len(stats.ByDomain) != 2 {
		t.Errorf("expected 2 by_domain entries, got %d", len(stats.ByDomain))
	}

	// Find each domain in the response and validate.
	domainMap := make(map[string]DomainStats)
	for _, d := range stats.ByDomain {
		domainMap[d.Name] = d
	}

	ex, ok := domainMap["example.com"]
	if !ok {
		t.Fatal("expected example.com in by_domain")
	}
	if ex.UserCount != 2 {
		t.Errorf("expected example.com user_count 2, got %d", ex.UserCount)
	}
	if !ex.HasKeys {
		t.Error("expected example.com has_keys true")
	}

	ot, ok := domainMap["other.org"]
	if !ok {
		t.Fatal("expected other.org in by_domain")
	}
	if ot.UserCount != 1 {
		t.Errorf("expected other.org user_count 1, got %d", ot.UserCount)
	}
	if ot.HasKeys {
		t.Error("expected other.org has_keys false")
	}
}

// createDashboardTestDomain sets up a minimal domain directory for dashboard tests.
func createDashboardTestDomain(t *testing.T, domainsPath, name, passwdContent string, withPubKey bool) {
	t.Helper()
	domainDir := filepath.Join(domainsPath, name)
	keysDir := filepath.Join(domainDir, "keys")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	config := "[auth]\ntype = \"passwd\"\n\n[msgstore]\ntype = \"maildir\"\n"
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(config), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwdContent), 0o640); err != nil {
		t.Fatal(err)
	}
	if withPubKey {
		if err := os.WriteFile(filepath.Join(keysDir, "admin.pub"), []byte("ssh-ed25519 AAAA test"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}
