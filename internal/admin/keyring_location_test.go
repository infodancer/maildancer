package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/internal/admin/keys"
)

// TestCreateUserKeys_WritesToUserDir verifies the write side of maildancer#82:
// a user keypair lands in the data-tree user directory as keyring.{pub,key},
// beside the maildir -- not in the config-tree keys directory.
func TestCreateUserKeys_WritesToUserDir(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "alice", "password123", false); err != nil {
		t.Fatal(err)
	}

	if _, err := p.CreateUserKeys("example.com", "alice", "password123"); err != nil {
		t.Fatalf("CreateUserKeys: %v", err)
	}

	userDir := filepath.Join(p.Data, "example.com", "users", "alice")
	for _, f := range []string{"keyring.pub", "keyring.key"} {
		if _, err := os.Stat(filepath.Join(userDir, f)); err != nil {
			t.Errorf("expected %s in the user data dir: %v", f, err)
		}
	}

	// Nothing must be written to the config-tree key dir for a user.
	legacy := filepath.Join(p.Config, "example.com", "keys", "alice.pub")
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("user key leaked into the config tree at %s (err=%v)", legacy, err)
	}
}

// TestUserKeyStatus_LegacyFallback verifies status still reports keys for an
// unmigrated user whose key lives only in the legacy config-tree key dir.
func TestUserKeyStatus_LegacyFallback(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "bob", "password123", false); err != nil {
		t.Fatal(err)
	}

	// Plant a legacy keypair in the config-tree keys dir, none in the user dir.
	pub, encPriv, err := keys.GenerateKeypair("password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveKeypair(p.domainKeysDir("example.com"), "bob", pub, encPriv); err != nil {
		t.Fatal(err)
	}

	status, err := p.UserKeyStatus("example.com", "bob")
	if err != nil {
		t.Fatalf("UserKeyStatus: %v", err)
	}
	if !status.Exists || !status.HasPrivate {
		t.Errorf("legacy key not reported: %+v", status)
	}
}

// TestDomainKeys_StayInConfigTree verifies domain keypairs are unaffected by
// the user-keyring relocation -- they remain in the config-tree keys dir.
func TestDomainKeys_StayInConfigTree(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateDomainKeys("example.com", "password123"); err != nil {
		t.Fatalf("CreateDomainKeys: %v", err)
	}

	keysDir := filepath.Join(p.Config, "example.com", "keys")
	for _, f := range []string{"domain.pub", "domain.key"} {
		if _, err := os.Stat(filepath.Join(keysDir, f)); err != nil {
			t.Errorf("expected domain %s in the config tree: %v", f, err)
		}
	}
	status, err := p.DomainKeyStatus("example.com")
	if err != nil || !status.Exists || !status.HasPrivate {
		t.Errorf("DomainKeyStatus = %+v, %v; want existing keypair", status, err)
	}
}

// TestDeleteUserKeys_RemovesBothLocations verifies key deletion clears both the
// data-tree keyring and any legacy config-tree key files.
func TestDeleteUserKeys_RemovesBothLocations(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser("example.com", "carol", "password123", true); err != nil {
		t.Fatal(err)
	}
	// Also plant a legacy file to confirm both paths are cleared.
	pub, encPriv, err := keys.GenerateKeypair("password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveKeypair(p.domainKeysDir("example.com"), "carol", pub, encPriv); err != nil {
		t.Fatal(err)
	}

	if err := p.DeleteUserKeys("example.com", "carol"); err != nil {
		t.Fatalf("DeleteUserKeys: %v", err)
	}

	if status, _ := p.UserKeyStatus("example.com", "carol"); status.Exists {
		t.Errorf("keys still present after delete: %+v", status)
	}
	userDir := filepath.Join(p.Data, "example.com", "users", "carol")
	if _, err := os.Stat(filepath.Join(userDir, "keyring.pub")); !os.IsNotExist(err) {
		t.Errorf("data-tree keyring not removed (err=%v)", err)
	}
	legacy := filepath.Join(p.Config, "example.com", "keys", "carol.pub")
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("legacy key not removed (err=%v)", err)
	}
}
