package main

import (
	"slices"
	"testing"

	"github.com/infodancer/maildancer/auth"
)

// TestPasswdAuthAgentRegistered guards the blank import of auth/passwd in
// main.go. session-manager constructs the "passwd" auth agent at runtime via
// the registry; the registration is an init() side-effect, so the package must
// be imported explicitly. It used to arrive transitively through
// credentials.Lookup, which stopped importing auth/passwd when uid/gid
// resolution moved to auth/identity (maildancer#101) -- silently crash-looping
// the daemon with "auth agent type not registered". This test compiles in
// package main, so removing the blank import makes it fail here, not in prod.
func TestPasswdAuthAgentRegistered(t *testing.T) {
	if !slices.Contains(auth.RegisteredAuthAgents(), "passwd") {
		t.Fatalf("passwd auth agent not registered; registered: %v -- is the blank import of auth/passwd missing from main.go?", auth.RegisteredAuthAgents())
	}
}
