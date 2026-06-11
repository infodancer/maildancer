package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth/domain"
)

// newDomainsTree creates a domains path with a single provisioned domain dir.
func newDomainsTree(t *testing.T, domainName string) string {
	t.Helper()
	domainsPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(domainsPath, domainName), 0o750); err != nil {
		t.Fatal(err)
	}
	return domainsPath
}

func TestRunForwardSubcommand_SetListDel(t *testing.T) {
	domainsPath := newDomainsTree(t, "example.com")

	if err := runForwardSubcommand([]string{"set", "alice@example.com", "bob@gmail.com"}, domainsPath); err != nil {
		t.Fatalf("set: %v", err)
	}
	fwds, _ := domain.ListDomainForwards(domainsPath, "example.com")
	if fwds["alice"] != "bob@gmail.com" {
		t.Fatalf("after set, forwards[alice] = %q, want bob@gmail.com", fwds["alice"])
	}

	// list should succeed (output not asserted here -- covered by helper tests).
	if err := runForwardSubcommand([]string{"list", "example.com"}, domainsPath); err != nil {
		t.Fatalf("list: %v", err)
	}

	if err := runForwardSubcommand([]string{"del", "alice@example.com"}, domainsPath); err != nil {
		t.Fatalf("del: %v", err)
	}
	fwds, _ = domain.ListDomainForwards(domainsPath, "example.com")
	if _, ok := fwds["alice"]; ok {
		t.Error("forward still present after del")
	}
}

func TestRunForwardSubcommand_Catchall(t *testing.T) {
	domainsPath := newDomainsTree(t, "example.com")
	if err := runForwardSubcommand([]string{"set", "*@example.com", "owner@example.com"}, domainsPath); err != nil {
		t.Fatalf("set catchall: %v", err)
	}
	fwds, _ := domain.ListDomainForwards(domainsPath, "example.com")
	if fwds["*"] != "owner@example.com" {
		t.Errorf("catchall = %q, want owner@example.com", fwds["*"])
	}
}

func TestRunForwardSubcommand_RejectsMultiTarget(t *testing.T) {
	domainsPath := newDomainsTree(t, "example.com")
	err := runForwardSubcommand([]string{"set", "alice@example.com", "a@x.com,b@y.com"}, domainsPath)
	if !errors.Is(err, domain.ErrMultiTargetForward) {
		t.Fatalf("err = %v, want ErrMultiTargetForward", err)
	}
}

func TestRunForwardSubcommand_Errors(t *testing.T) {
	domainsPath := newDomainsTree(t, "example.com")
	cases := []struct {
		name string
		args []string
	}{
		{"no action", []string{}},
		{"unknown action", []string{"frobnicate", "x"}},
		{"set wrong argc", []string{"set", "alice@example.com"}},
		{"set bad address", []string{"set", "alice", "bob@gmail.com"}},
		{"list wrong argc", []string{"list"}},
		{"del bad address", []string{"del", "alice"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runForwardSubcommand(tc.args, domainsPath); err == nil {
				t.Errorf("expected error for args %v, got nil", tc.args)
			}
		})
	}
}
