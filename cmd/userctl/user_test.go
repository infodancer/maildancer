package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/admin"
)

// authenticateUser runs a passwd-agent authentication against the test paths,
// wiring the data-tree keyring base as the daemons do.
func authenticateUser(t *testing.T, p admin.Paths, domain, username, password string) (*auth.AuthSession, error) {
	t.Helper()
	agent, err := passwd.NewAgent(
		filepath.Join(p.Config, domain, "passwd"),
		filepath.Join(p.Config, domain, "keys"))
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent = agent.WithUserKeyringBase(filepath.Join(p.Data, domain, "users"))
	defer func() { _ = agent.Close() }()
	return agent.Authenticate(context.Background(), username, password)
}

func TestRunUserSubcommand_Lifecycle(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}

	// add with uid allocation.
	if err := runUserSubcommand([]string{"add", "alice@example.com", "--password-stdin"}, p, strings.NewReader("password123\n")); err != nil {
		t.Fatalf("user add: %v", err)
	}
	users, err := p.ListUsers("example.com")
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers = %+v, %v", users, err)
	}
	if users[0].UID == 0 {
		t.Error("user created without uid")
	}

	// passwd reset preserves uid.
	if err := runUserSubcommand([]string{"passwd", "alice@example.com", "--password-stdin"}, p, strings.NewReader("newpassword1\n")); err != nil {
		t.Fatalf("user passwd: %v", err)
	}
	after, _ := p.ListUsers("example.com")
	if after[0].UID != users[0].UID {
		t.Errorf("uid changed on passwd reset: %d -> %d", users[0].UID, after[0].UID)
	}

	// key lifecycle.
	if err := runUserSubcommand([]string{"key", "create", "alice@example.com", "--password-stdin"}, p, strings.NewReader("newpassword1\n")); err != nil {
		t.Fatalf("user key create: %v", err)
	}
	status, err := p.UserKeyStatus("example.com", "alice")
	if err != nil || !status.Exists {
		t.Fatalf("user key missing: %+v, %v", status, err)
	}
	if err := runUserSubcommand([]string{"key", "show", "alice@example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("user key show: %v", err)
	}
	if err := runUserSubcommand([]string{"key", "del", "alice@example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("user key del: %v", err)
	}

	// list runs clean; del removes.
	if err := runUserSubcommand([]string{"list", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("user list: %v", err)
	}
	if err := runUserSubcommand([]string{"del", "alice@example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("user del: %v", err)
	}
	users, _ = p.ListUsers("example.com")
	if len(users) != 0 {
		t.Errorf("users after del = %+v", users)
	}
}

func TestRunUserSubcommand_AddWithKeys(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runUserSubcommand([]string{"add", "bob@example.com", "--gen-keys", "--password-stdin"}, p, strings.NewReader("password123\n")); err != nil {
		t.Fatalf("user add --gen-keys: %v", err)
	}
	status, err := p.UserKeyStatus("example.com", "bob")
	if err != nil || !status.Exists || !status.HasPrivate {
		t.Fatalf("keys not generated: %+v, %v", status, err)
	}
}

func TestRunUserSubcommand_Errors(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		args  []string
		stdin string
	}{
		{[]string{}, ""}, // missing action
		{[]string{"add", "noatsign", "--password-stdin"}, "pw"},                // bad address
		{[]string{"add", "x@nosuch.org", "--password-stdin"}, "password123\n"}, // missing domain
		{[]string{"add", "x@example.com", "--password-stdin"}, "short\n"},      // weak password
		{[]string{"add", "x@example.com", "--password-stdin"}, ""},             // empty stdin
		{[]string{"del", "ghost@example.com"}, ""},                             // missing user
		{[]string{"passwd", "ghost@example.com", "--password-stdin"}, "password123\n"},
		{[]string{"key", "create", "ghost@example.com", "--password-stdin"}, "password123\n"},
		{[]string{"bogus", "x@example.com"}, ""}, // unknown action
	}
	for _, c := range cases {
		if err := runUserSubcommand(c.args, p, strings.NewReader(c.stdin)); err == nil {
			t.Errorf("runUserSubcommand(%v) succeeded, want error", c.args)
		}
	}
}

func TestRunMigrateSubcommand(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runMigrateSubcommand([]string{"uids"}, p); err != nil {
		t.Fatalf("migrate uids: %v", err)
	}
	if err := runMigrateSubcommand([]string{"bogus"}, p); err == nil {
		t.Error("migrate bogus succeeded, want error")
	}
}

// TestRunUserSubcommand_PasswdWithKeys covers the password flows for a user
// with encryption keys: the default flow re-seals (two stdin lines: current,
// new), a bare reset is refused, and --reset regenerates the keypair.
func TestRunUserSubcommand_PasswdWithKeys(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runUserSubcommand([]string{"add", "alice@example.com", "--gen-keys", "--password-stdin"}, p, strings.NewReader("password123\n")); err != nil {
		t.Fatalf("user add --gen-keys: %v", err)
	}
	before, err := p.UserKeyStatus("example.com", "alice")
	if err != nil || !before.Exists || !before.HasPrivate {
		t.Fatalf("keys not provisioned: %+v, %v", before, err)
	}

	// Re-seal flow: --password-stdin supplies current then new.
	if err := runUserSubcommand([]string{"passwd", "alice@example.com", "--password-stdin"}, p, strings.NewReader("password123\nnewpassword1\n")); err != nil {
		t.Fatalf("user passwd (re-seal): %v", err)
	}
	after, _ := p.UserKeyStatus("example.com", "alice")
	if after.Fingerprint != before.Fingerprint {
		t.Errorf("re-seal must preserve the keypair: fingerprint %s -> %s", before.Fingerprint, after.Fingerprint)
	}

	// Wrong current password is refused.
	if err := runUserSubcommand([]string{"passwd", "alice@example.com", "--password-stdin"}, p, strings.NewReader("wrongpass99\nanotherpass1\n")); err == nil {
		t.Error("re-seal with wrong current password must fail")
	}

	// Admin reset regenerates the keypair.
	if err := runUserSubcommand([]string{"passwd", "alice@example.com", "--reset", "--password-stdin"}, p, strings.NewReader("resetpassword1\n")); err != nil {
		t.Fatalf("user passwd --reset: %v", err)
	}
	regen, _ := p.UserKeyStatus("example.com", "alice")
	if !regen.Exists || !regen.HasPrivate {
		t.Fatal("keys missing after --reset")
	}
	if regen.Fingerprint == after.Fingerprint {
		t.Error("--reset must regenerate the keypair, not reuse it")
	}
}

// TestRunUserSubcommand_AddIdempotent verifies the IaC reconcile contract:
// re-adding an existing user succeeds (exit 0) and does NOT alter the existing
// user -- the password is unchanged (still authenticates with the original).
func TestRunUserSubcommand_AddIdempotent(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runUserSubcommand([]string{"add", "alice@example.com", "--gen-keys", "--password-stdin"}, p, strings.NewReader("password123\n")); err != nil {
		t.Fatalf("first add: %v", err)
	}

	// Second add of the same user: must succeed (skip), not error.
	if err := runUserSubcommand([]string{"add", "alice@example.com", "--gen-keys", "--password-stdin"}, p, strings.NewReader("differentpw9\n")); err != nil {
		t.Fatalf("idempotent re-add must succeed, got: %v", err)
	}

	// The original password still authenticates -- the re-add did not reset it.
	session, err := authenticateUser(t, p, "example.com", "alice", "password123")
	if err != nil {
		t.Fatalf("original password broken after idempotent re-add: %v", err)
	}
	session.Clear()
}

// TestRunDomainSubcommand_CreateIdempotent verifies re-creating an existing
// domain succeeds (skip) rather than erroring.
func TestRunDomainSubcommand_CreateIdempotent(t *testing.T) {
	p := testPaths(t)
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := runDomainSubcommand([]string{"create", "example.com"}, p, strings.NewReader("")); err != nil {
		t.Fatalf("idempotent re-create must succeed, got: %v", err)
	}
}
