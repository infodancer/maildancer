package passwd

import (
	"os"
	"path/filepath"
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
