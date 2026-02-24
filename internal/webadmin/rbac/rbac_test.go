package rbac_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/internal/webadmin/rbac"
)

const sampleRolesContent = `
[admins.alice]
role = "super_admin"
domains = []

[admins.bob]
role = "domain_admin"
domains = ["example.com", "test.com"]
`

func TestLoadRolesEmpty(t *testing.T) {
	rs, err := rbac.LoadRoles("")
	if err != nil {
		t.Fatalf("LoadRoles(\"\") returned error: %v", err)
	}
	if rs == nil {
		t.Fatal("LoadRoles(\"\") returned nil store")
	}
	if !rs.IsSuperAdmin("anyuser") {
		t.Error("IsSuperAdmin should return true for any user when store is empty")
	}
}

func TestLoadRolesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles returned error: %v", err)
	}
	if rs == nil {
		t.Fatal("LoadRoles returned nil store")
	}

	alice, ok := rs.Admins["alice"]
	if !ok {
		t.Fatal("alice not found in store")
	}
	if alice.Role != rbac.RoleSuperAdmin {
		t.Errorf("alice.Role = %q, want %q", alice.Role, rbac.RoleSuperAdmin)
	}

	bob, ok := rs.Admins["bob"]
	if !ok {
		t.Fatal("bob not found in store")
	}
	if bob.Role != rbac.RoleDomainAdmin {
		t.Errorf("bob.Role = %q, want %q", bob.Role, rbac.RoleDomainAdmin)
	}
	if len(bob.Domains) != 2 {
		t.Errorf("bob.Domains len = %d, want 2", len(bob.Domains))
	}
}

func TestIsSuperAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	if !rs.IsSuperAdmin("alice") {
		t.Error("alice should be super_admin")
	}
	if rs.IsSuperAdmin("bob") {
		t.Error("bob should not be super_admin")
	}
	// unknown user: backward-compatible default is true
	if !rs.IsSuperAdmin("unknown") {
		t.Error("unknown user should return true for backward compatibility")
	}
}

func TestCanAccessDomain_SuperAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	if !rs.CanAccessDomain("alice", "example.com") {
		t.Error("super_admin alice should access example.com")
	}
	if !rs.CanAccessDomain("alice", "anything.org") {
		t.Error("super_admin alice should access any domain")
	}
}

func TestCanAccessDomain_DomainAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	if !rs.CanAccessDomain("bob", "example.com") {
		t.Error("bob should access example.com")
	}
	if !rs.CanAccessDomain("bob", "test.com") {
		t.Error("bob should access test.com")
	}
	if rs.CanAccessDomain("bob", "other.com") {
		t.Error("bob should not access other.com")
	}
}

func TestCanAccessDomain_Unknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	if rs.CanAccessDomain("unknown", "example.com") {
		t.Error("unknown user should not access any domain")
	}
}

func TestFilterDomains_SuperAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	input := []string{"example.com", "test.com", "other.com"}
	got := rs.FilterDomains("alice", input)
	if len(got) != len(input) {
		t.Errorf("FilterDomains for super_admin: got %d domains, want %d", len(got), len(input))
	}
	for i, d := range input {
		if got[i] != d {
			t.Errorf("FilterDomains[%d] = %q, want %q", i, got[i], d)
		}
	}
}

func TestFilterDomains_DomainAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(path, []byte(sampleRolesContent), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	rs, err := rbac.LoadRoles(path)
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	input := []string{"example.com", "other.com", "test.com"}
	got := rs.FilterDomains("bob", input)
	// should return example.com and test.com in input order
	want := []string{"example.com", "test.com"}
	if len(got) != len(want) {
		t.Fatalf("FilterDomains for domain_admin: got %v, want %v", got, want)
	}
	for i, d := range want {
		if got[i] != d {
			t.Errorf("FilterDomains[%d] = %q, want %q", i, got[i], d)
		}
	}
}

func TestFilterDomains_Empty(t *testing.T) {
	rs, err := rbac.LoadRoles("")
	if err != nil {
		t.Fatalf("LoadRoles: %v", err)
	}

	got := rs.FilterDomains("alice", []string{})
	if len(got) != 0 {
		t.Errorf("FilterDomains with empty input: got %v, want empty", got)
	}
}
