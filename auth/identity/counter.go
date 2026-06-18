package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// counterFile is the shared uid/gid allocation counter in the data tree.
const counterFile = ".uid-counter"

// firstID is the first id handed out; values below it are reserved for
// system/well-known ids.
const firstID = uint32(10000)

// allocateID atomically allocates the next id from {dataPath}/.uid-counter under
// an exclusive flock and bumps the counter. uid and gid share this counter, so
// the id space never collides between them. This is the identity package's own
// allocation primitive -- the allocator lives with the maps it feeds, not in a
// higher layer.
func allocateID(dataPath string) (uint32, error) {
	if err := os.MkdirAll(dataPath, 0o750); err != nil {
		return 0, fmt.Errorf("create data dir: %w", err)
	}
	counterPath := filepath.Join(dataPath, counterFile)

	f, err := os.OpenFile(counterPath, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return 0, fmt.Errorf("open id counter: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("lock id counter: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	raw := strings.TrimSpace(string(buf[:n]))

	var next uint32
	if raw == "" {
		next = firstID
	} else {
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse id counter %q: %w", raw, err)
		}
		next = uint32(v)
	}

	if err := f.Truncate(0); err != nil {
		return 0, fmt.Errorf("truncate id counter: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("seek id counter: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", next+1); err != nil {
		return 0, fmt.Errorf("write id counter: %w", err)
	}

	return next, nil
}
