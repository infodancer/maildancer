package passwd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash1, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// Must be verifiable by verifyPassword
	a := &Agent{}
	if !a.verifyPassword("secret", hash1) {
		t.Error("verifyPassword returned false for correct password")
	}
	if a.verifyPassword("wrong", hash1) {
		t.Error("verifyPassword returned true for wrong password")
	}

	// Each call should produce a different hash (different salt)
	hash2, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword second call: %v", err)
	}
	if hash1 == hash2 {
		t.Error("HashPassword produced identical hashes (salt not randomized)")
	}
}

func TestAddDeleteListUsers(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")

	// Start with an empty passwd file
	if err := os.WriteFile(passwdPath, []byte("# comment\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// List on empty file
	users, err := ListUsers(passwdPath)
	if err != nil {
		t.Fatalf("ListUsers empty: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}

	// Add first user
	if err := AddUser(passwdPath, "alice", "password1"); err != nil {
		t.Fatalf("AddUser alice: %v", err)
	}

	// Add second user
	if err := AddUser(passwdPath, "bob", "password2"); err != nil {
		t.Fatalf("AddUser bob: %v", err)
	}

	// Duplicate should fail
	if err := AddUser(passwdPath, "alice", "other"); err == nil {
		t.Error("expected error adding duplicate user, got nil")
	}

	// List should have both
	users, err = ListUsers(passwdPath)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "alice" || users[0].Mailbox != "alice" {
		t.Errorf("unexpected first user: %+v", users[0])
	}
	if users[1].Username != "bob" || users[1].Mailbox != "bob" {
		t.Errorf("unexpected second user: %+v", users[1])
	}

	// Delete alice
	if err := DeleteUser(passwdPath, "alice"); err != nil {
		t.Fatalf("DeleteUser alice: %v", err)
	}

	users, err = ListUsers(passwdPath)
	if err != nil {
		t.Fatalf("ListUsers after delete: %v", err)
	}
	if len(users) != 1 || users[0].Username != "bob" {
		t.Errorf("expected only bob after deleting alice, got %+v", users)
	}

	// Delete non-existent user should fail
	if err := DeleteUser(passwdPath, "nobody"); err == nil {
		t.Error("expected error deleting non-existent user, got nil")
	}
}

func TestAddUserRoundTrip(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	keyDir := filepath.Join(dir, "keys")

	if err := os.WriteFile(passwdPath, []byte(""), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := AddUser(passwdPath, "matthew", "hunter2"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	agent, err := NewAgent(passwdPath, keyDir)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	defer func() { _ = agent.Close() }()

	session, err := agent.Authenticate(t.Context(), "matthew", "hunter2")
	if err != nil {
		t.Fatalf("Authenticate with correct password: %v", err)
	}
	defer session.Clear()

	if session.User.Username != "matthew" {
		t.Errorf("expected username matthew, got %s", session.User.Username)
	}

	_, err = agent.Authenticate(t.Context(), "matthew", "wrong")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

func TestLookupUID(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")

	// Write entries: one with uid, one without, one with uid=0 explicitly
	content := "alice:HASH:alice:1001\nbob:HASH:bob:\ncarol:HASH:carol\n"
	if err := os.WriteFile(passwdPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	uid, err := LookupUID(passwdPath, "alice")
	if err != nil {
		t.Fatalf("LookupUID alice: %v", err)
	}
	if uid != 1001 {
		t.Errorf("expected uid 1001 for alice, got %d", uid)
	}

	uid, err = LookupUID(passwdPath, "bob")
	if err != nil {
		t.Fatalf("LookupUID bob: %v", err)
	}
	if uid != 0 {
		t.Errorf("expected uid 0 for bob (empty field), got %d", uid)
	}

	uid, err = LookupUID(passwdPath, "carol")
	if err != nil {
		t.Fatalf("LookupUID carol: %v", err)
	}
	if uid != 0 {
		t.Errorf("expected uid 0 for carol (no field), got %d", uid)
	}

	_, err = LookupUID(passwdPath, "nobody")
	if err == nil {
		t.Error("expected error for missing user, got nil")
	}
}

func TestListUsers_WithUID(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")

	content := "alice:HASH:alice:1001\nbob:HASH:bob:1002\n"
	if err := os.WriteFile(passwdPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	users, err := ListUsers(passwdPath)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Uid != 1001 {
		t.Errorf("expected alice uid 1001, got %d", users[0].Uid)
	}
	if users[1].Uid != 1002 {
		t.Errorf("expected bob uid 1002, got %d", users[1].Uid)
	}
}

func TestNewAgent_MissingPasswdFile(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	keyDir := filepath.Join(dir, "keys")

	// passwd file does not exist -- should succeed with no users
	agent, err := NewAgent(passwdPath, keyDir)
	if err != nil {
		t.Fatalf("NewAgent with missing passwd file: %v", err)
	}
	defer func() { _ = agent.Close() }()

	exists, err := agent.UserExists(t.Context(), "nobody")
	if err != nil {
		t.Fatalf("UserExists: %v", err)
	}
	if exists {
		t.Error("expected no users in empty agent")
	}
}

func TestSetPassword(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")

	// Four-field legacy entry; SetPassword must preserve the uid field.
	hash, err := HashPassword("oldpassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := os.WriteFile(passwdPath, []byte("bob:"+hash+":bob:10050\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := SetPassword(passwdPath, "bob", "newpassword"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// uid and mailbox survive the password change.
	uid, err := LookupUID(passwdPath, "bob")
	if err != nil {
		t.Fatalf("LookupUID: %v", err)
	}
	if uid != 10050 {
		t.Errorf("uid after SetPassword = %d, want 10050", uid)
	}

	agent, err := NewAgent(passwdPath, "")
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	defer func() { _ = agent.Close() }()
	if _, err := agent.Authenticate(context.Background(), "bob", "newpassword"); err != nil {
		t.Errorf("Authenticate with new password: %v", err)
	}
	if _, err := agent.Authenticate(context.Background(), "bob", "oldpassword"); err == nil {
		t.Error("old password still authenticates after SetPassword")
	}
}

func TestSetPassword_UserNotFound(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	if err := AddUser(passwdPath, "carol", "password123"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := SetPassword(passwdPath, "nosuchuser", "whatever"); err == nil {
		t.Error("expected error for missing user, got nil")
	}
}

func TestSetPassword_PreservesLegacyEntry(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	// Legacy three-field entry (no uid) with distinct mailbox, plus a comment line.
	hash, err := HashPassword("legacypw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	content := "# test users\ndave:" + hash + ":dave.smith\n"
	if err := os.WriteFile(passwdPath, []byte(content), 0o640); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	if err := SetPassword(passwdPath, "dave", "newpw"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	users, err := ListUsers(passwdPath)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Mailbox != "dave.smith" || users[0].Uid != 0 {
		t.Errorf("legacy entry not preserved: %+v", users)
	}

	data, err := os.ReadFile(passwdPath)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	if !strings.HasPrefix(string(data), "# test users\n") {
		t.Errorf("comment line not preserved:\n%s", data)
	}
}

// TestStripUIDs covers narrowing four-field entries back to three fields once
// the uid is authoritative in uid.toml.
func TestStripUIDs(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	hash, err := HashPassword("pw12345678")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// eve: four-field (uid to strip); frank: four-field (strip); carol: already
	// three-field (untouched); a comment line is preserved.
	content := "# users\n" +
		"eve:" + hash + ":eve.jones:10070\n" +
		"frank:" + hash + ":frank:10071\n" +
		"carol:" + hash + ":carol\n"
	if err := os.WriteFile(passwdPath, []byte(content), 0o640); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	// Strip only eve and frank (carol is not in the set and has no uid anyway).
	n, err := StripUIDs(passwdPath, []string{"eve", "frank"})
	if err != nil {
		t.Fatalf("StripUIDs: %v", err)
	}
	if n != 2 {
		t.Errorf("stripped = %d, want 2", n)
	}

	data, err := os.ReadFile(passwdPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "# users") {
		t.Errorf("comment not preserved:\n%s", got)
	}
	for _, want := range []string{
		"eve:" + hash + ":eve.jones\n",
		"frank:" + hash + ":frank\n",
		"carol:" + hash + ":carol\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, ":10070") || strings.Contains(got, ":10071") {
		t.Errorf("uid field not stripped:\n%s", got)
	}

	// Hash untouched: password still authenticates.
	agent, err := NewAgent(passwdPath, "")
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	defer func() { _ = agent.Close() }()
	if _, err := agent.Authenticate(context.Background(), "eve", "pw12345678"); err != nil {
		t.Errorf("Authenticate after StripUIDs: %v", err)
	}

	// Idempotent: a second strip changes nothing.
	n, err = StripUIDs(passwdPath, []string{"eve", "frank"})
	if err != nil || n != 0 {
		t.Errorf("second StripUIDs = (%d, %v), want (0, nil)", n, err)
	}
}
