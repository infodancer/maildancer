package uidalloc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const firstUID = uint32(10000)

// Allocate atomically allocates the next uid from the counter file at
// filepath.Join(domainsPath, ".uid-counter"). Returns an error if the
// counter file cannot be read or written.
func Allocate(domainsPath string) (uint32, error) {
	counterPath := filepath.Join(domainsPath, ".uid-counter")

	f, err := os.OpenFile(counterPath, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return 0, fmt.Errorf("open uid counter: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Exclusive lock -- blocks until granted.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("lock uid counter: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	// Read current value.
	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	raw := strings.TrimSpace(string(buf[:n]))

	var next uint32
	if raw == "" {
		next = firstUID
	} else {
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse uid counter %q: %w", raw, err)
		}
		next = uint32(v)
	}

	// Write incremented value.
	if err := f.Truncate(0); err != nil {
		return 0, fmt.Errorf("truncate uid counter: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("seek uid counter: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", next+1); err != nil {
		return 0, fmt.Errorf("write uid counter: %w", err)
	}

	return next, nil
}
