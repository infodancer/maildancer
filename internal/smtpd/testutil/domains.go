// Package testutil provides test helpers for creating domain fixtures.
package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/argon2"
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

// argon2id parameters matching auth/passwd. The hash string carries these
// inline, and auth/passwd.verifyPassword re-reads them from it, so the only
// requirement is internal consistency between the m=/t=/p= in the formatted
// string and the IDKey call below.
const (
	testArgon2Time    = 3
	testArgon2Memory  = 64 * 1024
	testArgon2Threads = 4
	testArgon2KeyLen  = 32
	testArgon2SaltLen = 16
)

// hashPassword produces an argon2id hash in the format auth/passwd reads:
// $argon2id$v=19$m=...,t=...,p=...$saltB64$hashB64 (RawStdEncoding).
//
// This duplicates auth/passwd's hashing because testutil sits inside the
// smtpd depguard boundary and cannot import auth/passwd. The previous
// hardcoded constant did not verify against "testpass" and ignored each
// user's Password field entirely (issue #56); computing per user makes the
// fixtures honest and lets tests use distinct passwords.
func hashPassword(password string) string {
	salt := make([]byte, testArgon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("testutil: read salt: " + err.Error())
	}
	hash := argon2.IDKey([]byte(password), salt,
		testArgon2Time, testArgon2Memory, testArgon2Threads, testArgon2KeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		testArgon2Memory, testArgon2Time, testArgon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

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

	// Create passwd file with user entries. Each user's password is hashed
	// for real, so the fixture authenticates through auth/passwd; an empty
	// Password falls back to "testpass" for the common case.
	passwdContent := "# Format: username:argon2id_hash:mailbox\n"
	for _, user := range domain.Users {
		mailbox := user.Mailbox
		if mailbox == "" {
			mailbox = user.Username
		}
		password := user.Password
		if password == "" {
			password = "testpass"
		}
		passwdContent += user.Username + ":" + hashPassword(password) + ":" + mailbox + "\n"
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
