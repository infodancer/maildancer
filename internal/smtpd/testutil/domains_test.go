package testutil

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// verifyArgon2 mirrors auth/passwd.verifyPassword: parse the encoded hash,
// re-derive with the password, constant-time compare. testutil cannot import
// auth/passwd (smtpd depguard boundary), so this replicates the parser to
// confirm the fixture hashes are actually verifiable -- the exact check the
// old hardcoded constant failed (issue #56).
func verifyArgon2(t *testing.T, password, encoded string) bool {
	t.Helper()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		t.Fatalf("malformed hash: %q", encoded)
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		t.Fatalf("parse params %q: %v", parts[3], err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// TestFixturePasswordsVerify pins #56: every generated passwd entry must
// actually verify against its plaintext password, including a non-default one.
func TestFixturePasswordsVerify(t *testing.T) {
	domains := []TestDomain{{
		Name: "example.com",
		Users: []TestUser{
			{Username: "alice", Password: "testpass"},
			{Username: "bob", Password: "a-different-password"},
			{Username: "carol"}, // empty -> defaults to "testpass"
		},
	}}
	basePath := SetupTestDomains(t, domains)

	data, err := os.ReadFile(filepath.Join(basePath, "example.com", "passwd"))
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	hashes := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			t.Fatalf("malformed passwd line: %q", line)
		}
		hashes[fields[0]] = fields[1]
	}

	cases := map[string]string{
		"alice": "testpass",
		"bob":   "a-different-password",
		"carol": "testpass",
	}
	for user, password := range cases {
		hash, ok := hashes[user]
		if !ok {
			t.Errorf("no passwd entry for %s", user)
			continue
		}
		if !verifyArgon2(t, password, hash) {
			t.Errorf("%s: hash does not verify against %q", user, password)
		}
		if verifyArgon2(t, "wrong-password", hash) {
			t.Errorf("%s: hash verifies against a wrong password", user)
		}
	}
}

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
