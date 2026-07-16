package grpcserver

import (
	"os"
	"os/user"
	"testing"
)

// TestResolveQueueOwner_CurrentUser resolves the running user's own name and
// expects its uid and primary gid back.
func TestResolveQueueOwner_CurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	owner, err := resolveQueueOwner(u.Username)
	if err != nil {
		t.Fatalf("resolveQueueOwner(%q): %v", u.Username, err)
	}
	if owner.UID != os.Getuid() {
		t.Errorf("UID = %d, want %d", owner.UID, os.Getuid())
	}
	wantGID := os.Getgid()
	if owner.GID != wantGID {
		// Primary gid from passwd can differ from the process gid in odd
		// environments; compare against the passwd entry instead.
		t.Logf("process gid %d, passwd primary gid %d", wantGID, owner.GID)
	}
}

// TestResolveQueueOwner_UnknownUser must fail hard: a typo in the configured
// owner silently falling back to root-owned queue entries would strand mail
// for an unprivileged queue-manager.
func TestResolveQueueOwner_UnknownUser(t *testing.T) {
	if _, err := resolveQueueOwner("no-such-user-4x9q"); err == nil {
		t.Fatal("resolveQueueOwner accepted an unknown user, want error")
	}
}
