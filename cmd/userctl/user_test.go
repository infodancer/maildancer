package main

import (
	"strings"
	"testing"
)

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
