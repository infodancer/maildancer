// Package testutil provides test helpers for creating domain fixtures.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUser represents a test user configuration.
type TestUser struct {
	Username string
	Password string // plaintext password (used for testing auth)
	Mailbox  string // defaults to Username if empty
}

// TestDomain represents a test domain configuration.
type TestDomain struct {
	Name  string
	Users []TestUser
}

// Pre-computed argon2id hash for "testpass" with salt "saltsaltsaltsalt".
// This avoids adding argon2 as a dependency to the test helper.
// Generated with: m=65536, t=3, p=4
const testpassHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$qqSCqQPLbO7RKU/qFwvGng"

// DefaultTestDomains returns the standard test domains (example.com, test.org).
// All users have the password "testpass".
func DefaultTestDomains() []TestDomain {
	return []TestDomain{
		{
			Name: "example.com",
			Users: []TestUser{
				{Username: "testuser", Password: "testpass"},
				{Username: "admin", Password: "testpass"},
			},
		},
		{
			Name: "test.org",
			Users: []TestUser{
				{Username: "user1", Password: "testpass"},
			},
		},
	}
}

// SetupTestDomains creates a complete domain provider test fixture.
// It creates the directory structure expected by FilesystemDomainProvider:
//
//	<basePath>/
//	├── <domain>/
//	│   ├── config.toml
//	│   ├── passwd
//	│   ├── keys/
//	│   └── users/
//	│       └── <user>/
//	│           └── Maildir/
//	│               ├── cur/
//	│               ├── new/
//	│               └── tmp/
//
// Returns the base path for use with FilesystemDomainProvider.
func SetupTestDomains(t *testing.T, domains []TestDomain) string {
	t.Helper()

	basePath := t.TempDir()

	for _, domain := range domains {
		if err := createDomain(basePath, domain); err != nil {
			t.Fatalf("failed to create test domain %s: %v", domain.Name, err)
		}
	}

	return basePath
}

// createDomain creates a single domain directory structure.
func createDomain(basePath string, domain TestDomain) error {
	domainPath := filepath.Join(basePath, domain.Name)

	// Create domain directory
	if err := os.MkdirAll(domainPath, 0755); err != nil {
		return err
	}

	// Create config.toml
	configContent := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"

[msgstore.options]
maildir_subdir = "Maildir"
`
	if err := os.WriteFile(filepath.Join(domainPath, "config.toml"), []byte(configContent), 0644); err != nil {
		return err
	}

	// Create keys directory
	if err := os.MkdirAll(filepath.Join(domainPath, "keys"), 0755); err != nil {
		return err
	}

	// Create passwd file with user entries
	passwdContent := "# Format: username:argon2id_hash:mailbox\n"
	passwdContent += "# Test users with password \"testpass\"\n"
	for _, user := range domain.Users {
		mailbox := user.Mailbox
		if mailbox == "" {
			mailbox = user.Username
		}
		passwdContent += user.Username + ":" + testpassHash + ":" + mailbox + "\n"
	}
	if err := os.WriteFile(filepath.Join(domainPath, "passwd"), []byte(passwdContent), 0644); err != nil {
		return err
	}

	// Create user directories with Maildir structure
	for _, user := range domain.Users {
		mailbox := user.Mailbox
		if mailbox == "" {
			mailbox = user.Username
		}
		maildirBase := filepath.Join(domainPath, "users", mailbox, "Maildir")
		for _, subdir := range []string{"cur", "new", "tmp"} {
			if err := os.MkdirAll(filepath.Join(maildirBase, subdir), 0755); err != nil {
				return err
			}
		}
	}

	return nil
}

// SetupDefaultTestDomains is a convenience function that creates the default
// test domains (example.com and test.org) and returns the base path.
func SetupDefaultTestDomains(t *testing.T) string {
	t.Helper()
	return SetupTestDomains(t, DefaultTestDomains())
}

// TestPassword is the password used for all default test users.
const TestPassword = "testpass"
