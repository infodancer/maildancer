package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupTestDomains(t *testing.T) {
	domains := []TestDomain{
		{
			Name: "example.com",
			Users: []TestUser{
				{Username: "user1", Password: "testpass"},
				{Username: "user2", Password: "testpass", Mailbox: "custombox"},
			},
		},
	}

	basePath := SetupTestDomains(t, domains)

	// Verify domain directory exists
	domainPath := filepath.Join(basePath, "example.com")
	if _, err := os.Stat(domainPath); os.IsNotExist(err) {
		t.Fatal("domain directory not created")
	}

	// Verify config.toml exists and has correct content
	configPath := filepath.Join(domainPath, "config.toml")
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config.toml: %v", err)
	}
	if !strings.Contains(string(configContent), `type = "passwd"`) {
		t.Error("config.toml missing auth type")
	}
	if !strings.Contains(string(configContent), `type = "maildir"`) {
		t.Error("config.toml missing msgstore type")
	}

	// Verify passwd file exists and has correct entries
	passwdPath := filepath.Join(domainPath, "passwd")
	passwdContent, err := os.ReadFile(passwdPath)
	if err != nil {
		t.Fatalf("failed to read passwd: %v", err)
	}
	if !strings.Contains(string(passwdContent), "user1:") {
		t.Error("passwd missing user1 entry")
	}
	if !strings.Contains(string(passwdContent), "user2:") {
		t.Error("passwd missing user2 entry")
	}
	if !strings.Contains(string(passwdContent), ":custombox") {
		t.Error("passwd missing custom mailbox for user2")
	}

	// Verify keys directory exists
	keysPath := filepath.Join(domainPath, "keys")
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		t.Fatal("keys directory not created")
	}

	// Verify Maildir structure for user1
	for _, subdir := range []string{"cur", "new", "tmp"} {
		path := filepath.Join(domainPath, "users", "user1", "Maildir", subdir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Maildir/%s not created for user1", subdir)
		}
	}

	// Verify Maildir structure for user2 uses custom mailbox
	for _, subdir := range []string{"cur", "new", "tmp"} {
		path := filepath.Join(domainPath, "users", "custombox", "Maildir", subdir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Maildir/%s not created for user2 with custom mailbox", subdir)
		}
	}
}

func TestSetupDefaultTestDomains(t *testing.T) {
	basePath := SetupDefaultTestDomains(t)

	// Verify example.com domain
	examplePath := filepath.Join(basePath, "example.com")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Fatal("example.com domain not created")
	}

	// Verify example.com users
	for _, user := range []string{"testuser", "admin"} {
		path := filepath.Join(examplePath, "users", user, "Maildir", "new")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("example.com user %s Maildir not created", user)
		}
	}

	// Verify test.org domain
	testOrgPath := filepath.Join(basePath, "test.org")
	if _, err := os.Stat(testOrgPath); os.IsNotExist(err) {
		t.Fatal("test.org domain not created")
	}

	// Verify test.org users
	path := filepath.Join(testOrgPath, "users", "user1", "Maildir", "new")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("test.org user user1 Maildir not created")
	}
}

func TestDefaultTestDomains(t *testing.T) {
	domains := DefaultTestDomains()

	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	// Check example.com
	var exampleCom *TestDomain
	for i := range domains {
		if domains[i].Name == "example.com" {
			exampleCom = &domains[i]
			break
		}
	}
	if exampleCom == nil {
		t.Fatal("example.com domain not found")
	}
	if len(exampleCom.Users) != 2 {
		t.Errorf("example.com: expected 2 users, got %d", len(exampleCom.Users))
	}

	// Check test.org
	var testOrg *TestDomain
	for i := range domains {
		if domains[i].Name == "test.org" {
			testOrg = &domains[i]
			break
		}
	}
	if testOrg == nil {
		t.Fatal("test.org domain not found")
	}
	if len(testOrg.Users) != 1 {
		t.Errorf("test.org: expected 1 user, got %d", len(testOrg.Users))
	}
}

func TestTestPassword(t *testing.T) {
	if TestPassword != "testpass" {
		t.Errorf("TestPassword = %q, want %q", TestPassword, "testpass")
	}
}
