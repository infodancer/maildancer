package domain

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

func TestFilesystemDomainProvider_GetDomain(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create a domain directory with config
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatalf("failed to create domain dir: %v", err)
	}

	// Create passwd file
	passwdPath := filepath.Join(domainDir, "passwd")
	passwdContent := "testuser:$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$qqSCqQPLbO7RKU/qFwvGng:testuser\n"
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to create passwd file: %v", err)
	}

	// Create keys directory
	keysDir := filepath.Join(domainDir, "keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("failed to create keys dir: %v", err)
	}

	// Create maildir
	maildirPath := filepath.Join(domainDir, "maildir")
	if err := os.MkdirAll(maildirPath, 0755); err != nil {
		t.Fatalf("failed to create maildir: %v", err)
	}

	// Create domain config
	configPath := filepath.Join(domainDir, "config.toml")
	configContent := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "maildir"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	// Create provider
	provider := NewFilesystemDomainProvider(tmpDir, nil)
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("failed to close provider: %v", err)
		}
	}()

	// Test GetDomain for existing domain
	d := provider.GetDomain("example.com")
	if d == nil {
		t.Fatal("expected domain to be found")
	}
	if d.Name != "example.com" {
		t.Errorf("expected domain name 'example.com', got %q", d.Name)
	}
	if d.AuthAgent == nil {
		t.Error("expected AuthAgent to be set")
	}
	if d.DeliveryAgent == nil {
		t.Error("expected DeliveryAgent to be set")
	}

	// Test UserExists
	ctx := context.Background()
	exists, err := d.AuthAgent.UserExists(ctx, "testuser")
	if err != nil {
		t.Fatalf("UserExists failed: %v", err)
	}
	if !exists {
		t.Error("expected testuser to exist")
	}

	exists, err = d.AuthAgent.UserExists(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("UserExists failed: %v", err)
	}
	if exists {
		t.Error("expected nonexistent user to not exist")
	}

	// Test GetDomain for non-existent domain
	d = provider.GetDomain("nonexistent.com")
	if d != nil {
		t.Error("expected nil for non-existent domain")
	}

	// Test case-insensitivity
	d = provider.GetDomain("EXAMPLE.COM")
	if d == nil {
		t.Error("expected domain lookup to be case-insensitive")
	}
}

func TestFilesystemDomainProvider_Domains(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create two domain directories
	for _, name := range []string{"example.com", "test.org"} {
		domainDir := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(domainDir, 0755); err != nil {
			t.Fatalf("failed to create domain dir: %v", err)
		}
		configPath := filepath.Join(domainDir, "config.toml")
		if err := os.WriteFile(configPath, []byte("[auth]\ntype = \"passwd\"\n"), 0644); err != nil {
			t.Fatalf("failed to create config: %v", err)
		}
	}

	// Create a directory without config (should not be listed)
	invalidDir := filepath.Join(tmpDir, "invalid")
	if err := os.MkdirAll(invalidDir, 0755); err != nil {
		t.Fatalf("failed to create invalid dir: %v", err)
	}

	// Create provider
	provider := NewFilesystemDomainProvider(tmpDir, nil)
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("failed to close provider: %v", err)
		}
	}()

	// Test Domains
	domains := provider.Domains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}

	// Check that both domains are listed
	found := make(map[string]bool)
	for _, d := range domains {
		found[d] = true
	}
	if !found["example.com"] {
		t.Error("expected example.com in domains list")
	}
	if !found["test.org"] {
		t.Error("expected test.org in domains list")
	}
}

func TestFilesystemDomainProvider_Caching(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatalf("failed to create domain dir: %v", err)
	}

	// Create minimal config
	passwdPath := filepath.Join(domainDir, "passwd")
	if err := os.WriteFile(passwdPath, []byte("user:hash:user\n"), 0644); err != nil {
		t.Fatalf("failed to create passwd: %v", err)
	}
	keysDir := filepath.Join(domainDir, "keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("failed to create keys dir: %v", err)
	}
	maildirPath := filepath.Join(domainDir, "maildir")
	if err := os.MkdirAll(maildirPath, 0755); err != nil {
		t.Fatalf("failed to create maildir: %v", err)
	}
	configPath := filepath.Join(domainDir, "config.toml")
	configContent := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "maildir"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	provider := NewFilesystemDomainProvider(tmpDir, nil)
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("failed to close provider: %v", err)
		}
	}()

	// First call should load the domain
	d1 := provider.GetDomain("example.com")
	if d1 == nil {
		t.Fatal("expected domain to be found")
	}

	// Second call should return cached domain
	d2 := provider.GetDomain("example.com")
	if d2 == nil {
		t.Fatal("expected domain to be found on second call")
	}

	// Both should be the same instance (pointer equality)
	if d1 != d2 {
		t.Error("expected cached domain to be returned")
	}
}

func TestDomain_Close(t *testing.T) {
	d := &Domain{
		Name:          "test.com",
		AuthAgent:     nil,
		DeliveryAgent: nil,
	}

	err := d.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
