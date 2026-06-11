package maildir

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	uidlistFile     = ".uidlist"
	uidlistTmpFile  = ".uidlist.tmp"
	uidlistLockFile = ".uidlist.lock"
	uidlistVersion  = 3
)

// uidEntry maps a persistent UID to a Maildir filename key.
type uidEntry struct {
	uid uint32
	key string
}

// uidList maintains the persistent UID-to-key mapping for a single Maildir folder.
type uidList struct {
	version     int
	uidValidity uint32
	uidNext     uint32
	entries     []uidEntry        // sorted by UID ascending
	keyToUID    map[string]uint32 // Maildir key → UID
	uidToKey    map[uint32]string // UID → Maildir key
}

// readUIDList parses a .uidlist file from the given Maildir directory.
// Returns nil if the file does not exist.
func readUIDList(dirPath string) (*uidList, error) {
	path := filepath.Join(dirPath, uidlistFile)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)

	// Parse header line: "3 V<uidvalidity> N<uidnext>"
	if !scanner.Scan() {
		return nil, fmt.Errorf("uidlist: empty file")
	}
	header := scanner.Text()
	ul, err := parseHeader(header)
	if err != nil {
		return nil, err
	}

	// Parse entry lines: "<uid> <key>"
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entry, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("uidlist: %w", err)
		}
		ul.entries = append(ul.entries, entry)
		ul.keyToUID[entry.key] = entry.uid
		ul.uidToKey[entry.uid] = entry.key
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ul, nil
}

// parseHeader parses the header line "3 V<validity> N<next>".
func parseHeader(line string) (*uidList, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return nil, fmt.Errorf("uidlist: invalid header: %q", line)
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("uidlist: invalid version: %q", parts[0])
	}

	if !strings.HasPrefix(parts[1], "V") {
		return nil, fmt.Errorf("uidlist: invalid validity field: %q", parts[1])
	}
	validity, err := strconv.ParseUint(parts[1][1:], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("uidlist: invalid validity value: %q", parts[1])
	}

	if !strings.HasPrefix(parts[2], "N") {
		return nil, fmt.Errorf("uidlist: invalid next field: %q", parts[2])
	}
	next, err := strconv.ParseUint(parts[2][1:], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("uidlist: invalid next value: %q", parts[2])
	}

	return &uidList{
		version:     version,
		uidValidity: uint32(validity),
		uidNext:     uint32(next),
		keyToUID:    make(map[string]uint32),
		uidToKey:    make(map[uint32]string),
	}, nil
}

// parseEntry parses an entry line "<uid> <key>".
func parseEntry(line string) (uidEntry, error) {
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return uidEntry{}, fmt.Errorf("invalid entry: %q", line)
	}
	uid, err := strconv.ParseUint(line[:idx], 10, 32)
	if err != nil {
		return uidEntry{}, fmt.Errorf("invalid uid in entry: %q", line)
	}
	key := line[idx+1:]
	if key == "" {
		return uidEntry{}, fmt.Errorf("empty key in entry: %q", line)
	}
	return uidEntry{uid: uint32(uid), key: key}, nil
}

// write atomically writes the uidlist to disk.
// Writes to .uidlist.tmp, fsyncs, then renames over .uidlist.
func (u *uidList) write(dirPath string) error {
	tmpPath := filepath.Join(dirPath, uidlistTmpFile)
	finalPath := filepath.Join(dirPath, uidlistFile)

	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)

	// Header
	if _, err := fmt.Fprintf(w, "%d V%d N%d\n", u.version, u.uidValidity, u.uidNext); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	// Entries (sorted by UID)
	for _, e := range u.entries {
		if _, err := fmt.Fprintf(w, "%d %s\n", e.uid, e.key); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}

	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, finalPath)
}

// reconcile updates the uidlist against the current set of Maildir keys in cur/.
// Returns true if any changes were made.
func (u *uidList) reconcile(curKeys []string) bool {
	curSet := make(map[string]bool, len(curKeys))
	for _, k := range curKeys {
		curSet[k] = true
	}

	changed := false

	// Remove entries for keys no longer in cur/.
	var kept []uidEntry
	for _, e := range u.entries {
		if curSet[e.key] {
			kept = append(kept, e)
		} else {
			delete(u.keyToUID, e.key)
			delete(u.uidToKey, e.uid)
			changed = true
		}
	}
	u.entries = kept

	// Find new keys not yet in the uidlist and sort them for deterministic
	// UID assignment. Maildir keys begin with a Unix timestamp, so lexicographic
	// sort gives chronological order.
	var newKeys []string
	for _, k := range curKeys {
		if _, ok := u.keyToUID[k]; !ok {
			newKeys = append(newKeys, k)
		}
	}
	if len(newKeys) > 0 {
		sort.Strings(newKeys)
		for _, k := range newKeys {
			e := uidEntry{uid: u.uidNext, key: k}
			u.entries = append(u.entries, e)
			u.keyToUID[k] = u.uidNext
			u.uidToKey[u.uidNext] = k
			u.uidNext++
			changed = true
		}
	}

	return changed
}

// bootstrapUIDList creates a new uidlist from the current contents of cur/.
// UIDValidity is set to the current Unix timestamp.
func bootstrapUIDList(curKeys []string) *uidList {
	sort.Strings(curKeys)

	ul := &uidList{
		version:     uidlistVersion,
		uidValidity: uint32(time.Now().Unix()),
		uidNext:     1,
		keyToUID:    make(map[string]uint32, len(curKeys)),
		uidToKey:    make(map[uint32]string, len(curKeys)),
	}

	for _, k := range curKeys {
		e := uidEntry{uid: ul.uidNext, key: k}
		ul.entries = append(ul.entries, e)
		ul.keyToUID[k] = ul.uidNext
		ul.uidToKey[ul.uidNext] = k
		ul.uidNext++
	}

	return ul
}

// lockUIDList acquires an exclusive flock on .uidlist.lock in the given directory.
// Returns the lock file which must be closed to release the lock.
func lockUIDList(dirPath string) (*os.File, error) {
	lockPath := filepath.Join(dirPath, uidlistLockFile)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// unlockUIDList releases the flock and closes the lock file.
func unlockUIDList(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

// loadOrBootstrapUIDList loads the uidlist for a Maildir directory, or
// bootstraps a new one if the file doesn't exist or is corrupt.
// curKeys should be the current Maildir keys from cur/.
// If the uidlist was bootstrapped or reconciled, it is written to disk.
// Callers must hold the uidlist lock.
func loadOrBootstrapUIDList(dirPath string, curKeys []string) (*uidList, error) {
	ul, err := readUIDList(dirPath)
	if err != nil {
		// Corrupt file -- log warning and bootstrap.
		_ = os.Remove(filepath.Join(dirPath, uidlistFile))
		ul = nil
	}

	if ul == nil {
		ul = bootstrapUIDList(curKeys)
		if err := ul.write(dirPath); err != nil {
			return nil, err
		}
		return ul, nil
	}

	if ul.reconcile(curKeys) {
		if err := ul.write(dirPath); err != nil {
			return nil, err
		}
	}

	return ul, nil
}

// curDirKeys returns the Maildir keys for all files in the cur/ subdirectory.
// The key is the filename up to (but not including) the info separator ':'.
func curDirKeys(dirPath string) ([]string, error) {
	curPath := filepath.Join(dirPath, "cur")
	entries, err := os.ReadDir(curPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Extract key: everything before the ':' info separator.
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		keys = append(keys, name)
	}
	return keys, nil
}
