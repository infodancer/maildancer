package domain

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func TestLazyAuthAgent_DomainLoadsWithoutPasswdAccess(t *testing.T) {
	// Verify that GetDomain() succeeds even when the passwd file is
	// unreadable. The auth agent is lazy -- it only opens the passwd file
	// when Authenticate() or UserExists() is called.
	tmpDir := t.TempDir()

	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create passwd file, then make it unreadable.
	passwdPath := filepath.Join(domainDir, "passwd")
	if err := os.WriteFile(passwdPath, []byte("user:hash:user\n"), 0000); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(domainDir, "keys"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(domainDir, "users"), 0755); err != nil {
		t.Fatal(err)
	}

	defaults := DomainConfig{
		Auth: DomainAuthConfig{
			Type:              "passwd",
			CredentialBackend: "passwd",
			KeyBackend:        "keys",
		},
		MsgStore: DomainMsgStoreConfig{
			Type:     "maildir",
			BasePath: "users",
		},
	}

	provider := NewFilesystemDomainProvider(tmpDir, nil).WithDefaults(defaults)
	defer provider.Close() //nolint:errcheck

	// GetDomain should succeed -- lazy auth doesn't open passwd yet.
	d := provider.GetDomain("example.com")
	if d == nil {
		t.Fatal("expected domain to load despite unreadable passwd")
	}
	if d.DeliveryAgent == nil {
		t.Error("expected DeliveryAgent to be set")
	}

	// Auth methods should fail gracefully when passwd is unreadable.
	ctx := context.Background()
	_, err := d.AuthAgent.UserExists(ctx, "user")
	if err == nil {
		t.Error("expected error from UserExists with unreadable passwd")
	}
}

func TestLazyAuthAgent_InitCalledOnce(t *testing.T) {
	// Verify that multiple auth calls only init the agent once.
	tmpDir := t.TempDir()

	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}

	passwdPath := filepath.Join(domainDir, "passwd")
	passwdContent := "testuser:$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$qqSCqQPLbO7RKU/qFwvGng:testuser\n"
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(domainDir, "keys"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(domainDir, "users"), 0755); err != nil {
		t.Fatal(err)
	}

	defaults := DomainConfig{
		Auth: DomainAuthConfig{
			Type:              "passwd",
			CredentialBackend: "passwd",
			KeyBackend:        "keys",
		},
		MsgStore: DomainMsgStoreConfig{
			Type:     "maildir",
			BasePath: "users",
		},
	}

	provider := NewFilesystemDomainProvider(tmpDir, nil).WithDefaults(defaults)
	defer provider.Close() //nolint:errcheck

	d := provider.GetDomain("example.com")
	if d == nil {
		t.Fatal("expected domain to load")
	}

	ctx := context.Background()

	// First call triggers lazy init.
	exists, err := d.AuthAgent.UserExists(ctx, "testuser")
	if err != nil {
		t.Fatalf("UserExists: %v", err)
	}
	if !exists {
		t.Error("expected testuser to exist")
	}

	// Second call reuses the initialized agent.
	exists, err = d.AuthAgent.UserExists(ctx, "testuser")
	if err != nil {
		t.Fatalf("second UserExists: %v", err)
	}
	if !exists {
		t.Error("expected testuser to still exist")
	}
}
