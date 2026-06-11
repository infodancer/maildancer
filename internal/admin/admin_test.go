package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/infodancer/maildancer/auth/passwd"
)

// newTestPaths returns a Paths with separate config and data volumes,
// mimicking the production split layout.
func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		Config: filepath.Join(root, "config"),
		Data:   filepath.Join(root, "data"),
	}
	if err := os.MkdirAll(p.Config, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Data, 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidation(t *testing.T) {
	cases := []struct {
		fn    func(string) bool
		input string
		want  bool
	}{
		{ValidDomainName, "example.com", true},
		{ValidDomainName, "sub.example-two.org", true},
		{ValidDomainName, "EXAMPLE.COM", false},
		{ValidDomainName, "nodots", false},
		{ValidDomainName, "../etc", false},
		{ValidDomainName, "a/b.com", false},
		{ValidDomainName, "", false},
		{ValidUsername, "alice", true},
		{ValidUsername, "alice.smith-jones_2", true},
		{ValidUsername, ".alice", false},
		{ValidUsername, "a/../b", false},
		{ValidUsername, "", false},
		{ValidPassword, "12345678", true},
		{ValidPassword, "1234567", false},
	}
	for _, c := range cases {
		if got := c.fn(c.input); got != c.want {
			t.Errorf("validate(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestCreateDomain(t *testing.T) {
	p := newTestPaths(t)

	gid, err := p.CreateDomain("example.com")
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if gid < 10000 {
		t.Errorf("gid = %d, want >= 10000", gid)
	}

	// Config volume anatomy.
	for _, rel := range []string{"config.toml", "passwd", "keys"} {
		if _, err := os.Stat(filepath.Join(p.Config, "example.com", rel)); err != nil {
			t.Errorf("missing config-volume %s: %v", rel, err)
		}
	}
	// Data volume anatomy.
	for _, rel := range []string{"config.toml", "users"} {
		if _, err := os.Stat(filepath.Join(p.Data, "example.com", rel)); err != nil {
			t.Errorf("missing data-volume %s: %v", rel, err)
		}
	}

	// GetDomain reads it back, gid included.
	info, err := p.GetDomain("example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if info.GID != gid || info.AuthType != "passwd" || info.StoreType != "maildir" || info.UserCount != 0 {
		t.Errorf("GetDomain = %+v, want gid=%d passwd/maildir/0 users", info, gid)
	}

	// Duplicate creation fails.
	if _, err := p.CreateDomain("example.com"); !errors.Is(err, ErrDomainExists) {
		t.Errorf("duplicate CreateDomain err = %v, want ErrDomainExists", err)
	}
	// Invalid name fails.
	if _, err := p.CreateDomain("../escape"); !errors.Is(err, ErrInvalidDomainName) {
		t.Errorf("invalid CreateDomain err = %v, want ErrInvalidDomainName", err)
	}

	// Second domain gets a distinct gid.
	gid2, err := p.CreateDomain("other.org")
	if err != nil {
		t.Fatalf("CreateDomain other.org: %v", err)
	}
	if gid2 == gid {
		t.Errorf("gid reuse: both domains got %d", gid)
	}
}

func TestDeleteDomain(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	// Refuses while users exist.
	err := p.DeleteDomain("example.com", false)
	if !errors.Is(err, ErrDomainHasUsers) {
		t.Fatalf("DeleteDomain err = %v, want ErrDomainHasUsers", err)
	}
	if !strings.Contains(err.Error(), "1 users") {
		t.Errorf("error should carry the count: %v", err)
	}

	// Force deletes; data volume survives.
	if err := p.DeleteDomain("example.com", true); err != nil {
		t.Fatalf("DeleteDomain force: %v", err)
	}
	if p.DomainExists("example.com") {
		t.Error("config-volume domain dir still present after delete")
	}
	if _, err := os.Stat(filepath.Join(p.Data, "example.com", "users")); err != nil {
		t.Errorf("data volume should survive domain deletion: %v", err)
	}

	if err := p.DeleteDomain("example.com", false); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("deleting missing domain err = %v, want ErrDomainNotFound", err)
	}
}

func TestListDomains(t *testing.T) {
	p := newTestPaths(t)
	if list, err := p.ListDomains(); err != nil || len(list) != 0 {
		t.Fatalf("empty ListDomains = %v, %v", list, err)
	}
	if _, err := p.CreateDomain("a.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateDomain("b.org"); err != nil {
		t.Fatal(err)
	}
	// Hidden entries (.uid-counter dirs etc.) are skipped.
	if err := os.MkdirAll(filepath.Join(p.Config, ".hidden"), 0o750); err != nil {
		t.Fatal(err)
	}

	list, err := p.ListDomains()
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListDomains len = %d, want 2: %+v", len(list), list)
	}
}

func TestCreateUser(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	res, err := p.CreateUser("example.com", "alice", "password123", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if res.UID < 10000 {
		t.Errorf("uid = %d, want >= 10000", res.UID)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}

	// Maildir directory created in the data volume.
	if _, err := os.Stat(filepath.Join(p.Data, "example.com", "users", "alice")); err != nil {
		t.Errorf("maildir not created: %v", err)
	}

	// uid is in the passwd entry and the password authenticates.
	uid, err := passwd.LookupUID(filepath.Join(p.Config, "example.com", "passwd"), "alice")
	if err != nil || uid != res.UID {
		t.Errorf("LookupUID = %d, %v; want %d", uid, err, res.UID)
	}

	// Error cases.
	if _, err := p.CreateUser("example.com", "alice", "password123", false); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate user err = %v, want ErrUserExists", err)
	}
	if _, err := p.CreateUser("example.com", "bob", "short", false); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak password err = %v, want ErrWeakPassword", err)
	}
	if _, err := p.CreateUser("nodomain.net", "bob", "password123", false); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("missing domain err = %v, want ErrDomainNotFound", err)
	}
	if _, err := p.CreateUser("example.com", "../bob", "password123", false); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("invalid username err = %v, want ErrInvalidUsername", err)
	}
}

func TestCreateUserWithKeys(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	res, err := p.CreateUser("example.com", "alice", "password123", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !res.KeysGenerated {
		t.Fatalf("KeysGenerated = false, warnings: %v", res.Warnings)
	}

	status, err := p.UserKeyStatus("example.com", "alice")
	if err != nil {
		t.Fatalf("UserKeyStatus: %v", err)
	}
	if !status.Exists || !status.HasPrivate || status.Fingerprint == "" {
		t.Errorf("key status = %+v, want existing keypair with fingerprint", status)
	}

	users, err := p.ListUsers("example.com")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || !users[0].HasKeys {
		t.Errorf("ListUsers = %+v, want alice with keys", users)
	}
}

func TestDeleteUser(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", true); err != nil {
		t.Fatal(err)
	}

	if err := p.DeleteUser("example.com", "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	users, err := p.ListUsers("example.com")
	if err != nil || len(users) != 0 {
		t.Errorf("ListUsers after delete = %+v, %v", users, err)
	}
	// Key files removed too.
	status, err := p.UserKeyStatus("example.com", "alice")
	if err != nil || status.Exists {
		t.Errorf("keys survived user deletion: %+v, %v", status, err)
	}

	if err := p.DeleteUser("example.com", "alice"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("deleting missing user err = %v, want ErrUserNotFound", err)
	}
}

func TestResetPassword(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := p.CreateUser("example.com", "alice", "oldpassword", false)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.ResetPassword("example.com", "alice", "newpassword"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// uid preserved.
	uid, err := passwd.LookupUID(filepath.Join(p.Config, "example.com", "passwd"), "alice")
	if err != nil || uid != res.UID {
		t.Errorf("uid after reset = %d, %v; want %d", uid, err, res.UID)
	}

	if err := p.ResetPassword("example.com", "nobody", "newpassword"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("reset for missing user err = %v, want ErrUserNotFound", err)
	}
	if err := p.ResetPassword("example.com", "alice", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak reset err = %v, want ErrWeakPassword", err)
	}
}

func TestDomainKeys(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	status, err := p.DomainKeyStatus("example.com")
	if err != nil {
		t.Fatalf("DomainKeyStatus: %v", err)
	}
	if status.Exists {
		t.Fatalf("new domain reports keys: %+v", status)
	}

	fp, err := p.CreateDomainKeys("example.com", "keypassword")
	if err != nil {
		t.Fatalf("CreateDomainKeys: %v", err)
	}
	if fp == "" {
		t.Error("empty fingerprint")
	}

	status, err = p.DomainKeyStatus("example.com")
	if err != nil || !status.Exists || !status.HasPrivate || status.Fingerprint != fp {
		t.Errorf("DomainKeyStatus = %+v, %v; want existing with fingerprint %s", status, err, fp)
	}

	if _, err := p.CreateDomainKeys("example.com", ""); !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("empty password err = %v, want ErrPasswordRequired", err)
	}

	if err := p.DeleteDomainKeys("example.com"); err != nil {
		t.Fatalf("DeleteDomainKeys: %v", err)
	}
	status, _ = p.DomainKeyStatus("example.com")
	if status.Exists {
		t.Error("domain keys survived deletion")
	}
}

func TestUserKeysLifecycle(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	// Keys for a nonexistent user are refused.
	if _, err := p.CreateUserKeys("example.com", "ghost", "password123"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("keys for missing user err = %v, want ErrUserNotFound", err)
	}

	fp, err := p.CreateUserKeys("example.com", "alice", "password123")
	if err != nil {
		t.Fatalf("CreateUserKeys: %v", err)
	}
	if fp == "" {
		t.Error("empty fingerprint")
	}
	if err := p.DeleteUserKeys("example.com", "alice"); err != nil {
		t.Fatalf("DeleteUserKeys: %v", err)
	}
	status, _ := p.UserKeyStatus("example.com", "alice")
	if status.Exists {
		t.Error("user keys survived deletion")
	}
}

func TestMigrateUIDs(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	// Simulate a pre-uid domain: legacy passwd entries and no data-volume gid.
	hash, err := passwd.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	passwdPath := filepath.Join(p.Config, "example.com", "passwd")
	legacy := "# legacy\nalice:" + hash + ":alice\nbob:" + hash + ":bob:0\ncarol:" + hash + ":carol:10005\n"
	if err := os.WriteFile(passwdPath, []byte(legacy), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.Data, "example.com", "config.toml")); err != nil {
		t.Fatal(err)
	}

	result, err := p.MigrateUIDs()
	if err != nil {
		t.Fatalf("MigrateUIDs: %v", err)
	}
	if result.DomainsMigrated != 1 {
		t.Errorf("DomainsMigrated = %d, want 1", result.DomainsMigrated)
	}
	if result.UsersMigrated != 2 {
		t.Errorf("UsersMigrated = %d, want 2 (alice and bob, not carol): %+v", result.UsersMigrated, result)
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors = %v", result.Errors)
	}

	// All users now have uids; carol's is untouched.
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Uid == 0 {
			t.Errorf("user %s still has uid 0", u.Username)
		}
		if u.Username == "carol" && u.Uid != 10005 {
			t.Errorf("carol's uid changed to %d", u.Uid)
		}
	}

	// Idempotent: a second run migrates nothing.
	result, err = p.MigrateUIDs()
	if err != nil {
		t.Fatalf("second MigrateUIDs: %v", err)
	}
	if result.DomainsMigrated != 0 || result.UsersMigrated != 0 {
		t.Errorf("second run migrated: %+v", result)
	}
}

func TestConcurrentCreateUser(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	// Concurrent creations must neither corrupt the passwd file nor reuse uids.
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = p.CreateUser("example.com", fmt.Sprintf("user%d", i), "password123", false)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("CreateUser user%d: %v", i, err)
		}
	}

	users, err := p.ListUsers("example.com")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != n {
		t.Fatalf("got %d users, want %d", len(users), n)
	}
	seen := map[uint32]string{}
	for _, u := range users {
		if prev, dup := seen[u.UID]; dup {
			t.Errorf("uid %d assigned to both %s and %s", u.UID, prev, u.Username)
		}
		seen[u.UID] = u.Username
	}
}
