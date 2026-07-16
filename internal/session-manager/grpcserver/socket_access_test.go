package grpcserver

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// currentGroupName resolves the current user's primary group name.
func currentGroupName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatalf("lookup group: %v", err)
	}
	return g.Name
}

// listenSocket creates a unix socket in a temp dir and returns its path.
// The listener is closed via t.Cleanup; the socket file stays for perm checks.
func listenSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	// Keep the socket file around after close for stat purposes.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = ln.Close() })
	return path
}

func socketMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	return info.Mode().Perm()
}

func TestApplySocketAccess_NoGroup(t *testing.T) {
	path := listenSocket(t)

	if err := applySocketAccess(path, ""); err != nil {
		t.Fatalf("applySocketAccess: %v", err)
	}
	if mode := socketMode(t, path); mode != 0600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}
}

func TestApplySocketAccess_UnknownGroupFallsBack(t *testing.T) {
	path := listenSocket(t)

	// A missing group must warn and fall back to root-only, not error and
	// not open the socket up.
	if err := applySocketAccess(path, "nosuchgroup-zz"); err != nil {
		t.Fatalf("applySocketAccess: %v", err)
	}
	if mode := socketMode(t, path); mode != 0600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}
}

func TestApplySocketAccess_GroupOffRootFallsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test asserts the off-root fallback; running as root")
	}
	path := listenSocket(t)

	// Off-root the chown cannot succeed, so the socket must stay 0600 even
	// when the group exists.
	if err := applySocketAccess(path, currentGroupName(t)); err != nil {
		t.Fatalf("applySocketAccess: %v", err)
	}
	if mode := socketMode(t, path); mode != 0600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}
}
