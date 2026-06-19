package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newManager returns a Manager over two temp trees (config, data).
func newManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(cfg, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o750); err != nil {
		t.Fatal(err)
	}
	return NewManager(cfg, data)
}

func TestDomainGID_MissingIsHardError(t *testing.T) {
	m := newManager(t)
	if _, err := m.DomainGID("example.com"); !errors.Is(err, ErrNoGID) {
		t.Fatalf("want ErrNoGID for unallocated domain, got %v", err)
	}
}

func TestUserUID_MissingIsHardError(t *testing.T) {
	m := newManager(t)
	if _, err := m.UserUID("example.com", "alice"); !errors.Is(err, ErrNoUID) {
		t.Fatalf("want ErrNoUID for unallocated user, got %v", err)
	}
}

func TestAllocateDomainGID_RoundTrip(t *testing.T) {
	m := newManager(t)
	gid, err := m.AllocateDomainGID("example.com")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if gid < firstID {
		t.Fatalf("gid %d below firstID %d", gid, firstID)
	}
	// Read back through the free function (the daemon's path).
	got, err := DomainGID(m.Config, "example.com")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != gid {
		t.Fatalf("read back %d, allocated %d", got, gid)
	}
}

func TestAllocateDomainGID_AllocateOnce(t *testing.T) {
	m := newManager(t)
	first, err := m.AllocateDomainGID("example.com")
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	again, err := m.AllocateDomainGID("example.com")
	if !errors.Is(err, ErrGIDExists) {
		t.Fatalf("want ErrGIDExists on re-allocate, got %v", err)
	}
	if again != first {
		t.Fatalf("re-allocate returned %d, want existing %d", again, first)
	}
}

func TestAllocateDomainGID_DistinctIDs(t *testing.T) {
	m := newManager(t)
	a, err := m.AllocateDomainGID("a.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.AllocateDomainGID("b.example")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("both domains got gid %d", a)
	}
}

func TestUIDAndGIDShareCounter(t *testing.T) {
	m := newManager(t)
	gid, err := m.AllocateDomainGID("example.com")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := m.AllocateUserUID("example.com", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if uid == gid {
		t.Fatalf("uid and gid collided at %d -- they must share one counter", uid)
	}
}

func TestSetDomainGID_AdoptThenIdempotent(t *testing.T) {
	m := newManager(t)
	if err := m.SetDomainGID("example.com", 10014); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	got, err := m.DomainGID("example.com")
	if err != nil || got != 10014 {
		t.Fatalf("got (%d,%v), want (10014,nil)", got, err)
	}
	// Same value again is a no-op, not an error.
	if err := m.SetDomainGID("example.com", 10014); err != nil {
		t.Fatalf("idempotent set: %v", err)
	}
}

func TestSetDomainGID_ConflictRefused(t *testing.T) {
	m := newManager(t)
	if err := m.SetDomainGID("example.com", 10014); err != nil {
		t.Fatal(err)
	}
	if err := m.SetDomainGID("example.com", 10036); !errors.Is(err, ErrGIDExists) {
		t.Fatalf("want ErrGIDExists on conflicting set, got %v", err)
	}
	got, _ := m.DomainGID("example.com")
	if got != 10014 {
		t.Fatalf("conflicting set changed gid to %d, want 10014 unchanged", got)
	}
}

func TestSetUserUID_ConflictRefused(t *testing.T) {
	m := newManager(t)
	if err := m.SetUserUID("example.com", "alice", 10026); err != nil {
		t.Fatal(err)
	}
	if err := m.SetUserUID("example.com", "alice", 10099); !errors.Is(err, ErrUIDExists) {
		t.Fatalf("want ErrUIDExists, got %v", err)
	}
}

func TestRemoveUser(t *testing.T) {
	m := newManager(t)
	if _, err := m.AllocateUserUID("example.com", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveUser("example.com", "alice"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := m.UserUID("example.com", "alice"); !errors.Is(err, ErrNoUID) {
		t.Fatalf("want ErrNoUID after remove, got %v", err)
	}
	// Removing a missing user is not an error.
	if err := m.RemoveUser("example.com", "ghost"); err != nil {
		t.Fatalf("remove missing: %v", err)
	}
}

func TestRemoveDomainGID(t *testing.T) {
	m := newManager(t)
	if _, err := m.AllocateDomainGID("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveDomainGID("example.com"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := m.DomainGID("example.com"); !errors.Is(err, ErrNoGID) {
		t.Fatalf("want ErrNoGID after remove, got %v", err)
	}
	// Removing a missing domain is not an error.
	if err := m.RemoveDomainGID("ghost.example"); err != nil {
		t.Fatalf("remove missing: %v", err)
	}
}

// TestGIDMapFormat checks the on-disk file: a guard header, quoted keys, sorted.
func TestGIDMapFormat(t *testing.T) {
	m := newManager(t)
	if err := m.SetDomainGID("zeta.example", 10020); err != nil {
		t.Fatal(err)
	}
	if err := m.SetDomainGID("alpha.example", 10010); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(m.Config, GIDMapFile))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "# domain = gid") {
		t.Errorf("missing guard header:\n%s", s)
	}
	if !strings.Contains(s, `"alpha.example" = 10010`) {
		t.Errorf("missing quoted alpha entry:\n%s", s)
	}
	if !strings.Contains(s, `"zeta.example" = 10020`) {
		t.Errorf("missing quoted zeta entry:\n%s", s)
	}
	// Sorted: alpha must precede zeta for a stable diff.
	if strings.Index(s, "alpha.example") > strings.Index(s, "zeta.example") {
		t.Errorf("entries not sorted:\n%s", s)
	}
}

// TestMapsAreSeparateFiles confirms uid lives per-domain and gid at top level.
func TestMapsAreSeparateFiles(t *testing.T) {
	m := newManager(t)
	if _, err := m.AllocateDomainGID("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AllocateUserUID("example.com", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Config, GIDMapFile)); err != nil {
		t.Errorf("gid.toml not at config root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Config, "example.com", UIDMapFile)); err != nil {
		t.Errorf("uid.toml not under domain dir: %v", err)
	}
}
