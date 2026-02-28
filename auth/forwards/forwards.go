// Package forwards provides mail forwarding rule loading and resolution.
// Rules are loaded from plain-text files and queried by local part.
package forwards

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ForwardMap holds mail forwarding rules loaded from a forwards file.
//
// File format (one rule per line):
//
//	localpart:target1@domain,target2@domain
//	*:catchall@domain
//	# comment lines and blank lines are ignored
//
// The * wildcard is a catchall for any localpart not matched exactly.
// Multiple targets may be listed as a comma-separated value.
type ForwardMap struct {
	exact    map[string][]string // localpart → forwarding targets
	catchall []string            // targets for the * wildcard
}

// Load reads forwarding rules from path.
// A missing file is treated as empty (no forwards), not an error.
func Load(path string) (*ForwardMap, error) {
	m := &ForwardMap{exact: make(map[string][]string)}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, fmt.Errorf("open forwards file: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue // malformed line, skip silently
		}
		key = strings.TrimSpace(strings.ToLower(key))

		var targets []string
		for _, t := range strings.Split(value, ",") {
			t = strings.TrimSpace(strings.ToLower(t))
			if t != "" {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			continue
		}

		if key == "*" {
			m.catchall = targets
		} else {
			m.exact[key] = targets
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read forwards file: %w", err)
	}

	return m, nil
}

// LoadTargets reads a per-user forwards file.
// The file contains one forwarding target address per line with no localpart
// key — the filename itself is the key (the localpart).
// Returns nil, nil if the file does not exist.
func LoadTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open user forwards file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if t != "" && !strings.HasPrefix(t, "#") {
			targets = append(targets, t)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read user forwards file: %w", err)
	}
	return targets, nil
}

// FromMap constructs a ForwardMap from a map of localpart to comma-separated
// forwarding targets. This is the in-memory equivalent of Load, for rules
// stored in a [forwards] TOML section rather than a separate file.
// The special key "*" sets the catchall rule. A nil map produces an empty map.
func FromMap(m map[string]string) *ForwardMap {
	fm := &ForwardMap{exact: make(map[string][]string)}
	for k, v := range m {
		var targets []string
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			continue
		}
		if k == "*" {
			fm.catchall = targets
		} else {
			fm.exact[strings.ToLower(k)] = targets
		}
	}
	return fm
}

// Resolve returns the forwarding targets for localpart.
// It checks for an exact match first, then falls back to the catchall (*).
// Returns (nil, false) if no forwarding rule applies.
func (m *ForwardMap) Resolve(localpart string) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	localpart = strings.ToLower(localpart)
	if targets, ok := m.exact[localpart]; ok {
		return targets, true
	}
	if len(m.catchall) > 0 {
		return m.catchall, true
	}
	return nil, false
}

// UserExists reports whether localpart has a forwarding rule (exact or catchall).
func (m *ForwardMap) UserExists(localpart string) bool {
	_, ok := m.Resolve(localpart)
	return ok
}

// Empty reports whether the map has no forwarding rules at all.
func (m *ForwardMap) Empty() bool {
	if m == nil {
		return true
	}
	return len(m.exact) == 0 && len(m.catchall) == 0
}
