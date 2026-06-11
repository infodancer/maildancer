package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockDomain takes an exclusive cross-process lock for mutating operations on
// a domain's config-volume files (passwd, keys). The lock is a flock on
// {config}/{domain}/.lock, so concurrent webadmin and userctl processes
// serialize against each other -- an in-process mutex cannot provide that.
// Blocks until the lock is granted. The caller must call the returned unlock.
func (p Paths) lockDomain(domain string) (func(), error) {
	lockPath := filepath.Join(p.Config, domain, ".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open domain lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock domain: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
