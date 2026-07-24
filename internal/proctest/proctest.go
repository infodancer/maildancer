// Package proctest provides Linux /proc-based helpers for asserting that a
// daemon handles each accepted connection in a child process rather than
// in-process. infodancer/docs/mail-security-model.md requires the listener to
// fork a protocol-handler subprocess per connection; these helpers let a test
// observe whether that actually happened (issue #179).
package proctest

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Children returns the live direct children of the current process, read from
// /proc/self/task/*/children (CONFIG_PROC_CHILDREN, present on standard
// distribution kernels).
func Children() (map[int]bool, error) {
	tasks, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		return nil, fmt.Errorf("glob task children: %w", err)
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("no /proc/self/task/*/children files; procfs unavailable or CONFIG_PROC_CHILDREN missing")
	}
	pids := make(map[int]bool)
	for _, path := range tasks {
		data, err := os.ReadFile(path)
		if err != nil {
			// The thread may have exited between glob and read.
			continue
		}
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("parse pid %q in %s: %w", field, path, err)
			}
			pids[pid] = true
		}
	}
	return pids, nil
}

// WaitForNewChildren polls until at least want direct children not present in
// baseline exist, and returns them. On timeout it returns an error stating how
// many it found: for a daemon that serves connections in-process, that count
// stays at zero no matter how long the poll runs.
func WaitForNewChildren(baseline map[int]bool, want int, timeout time.Duration) ([]int, error) {
	deadline := time.Now().Add(timeout)
	for {
		current, err := Children()
		if err != nil {
			return nil, err
		}
		var fresh []int
		for pid := range current {
			if !baseline[pid] {
				fresh = append(fresh, pid)
			}
		}
		if len(fresh) >= want {
			return fresh, nil
		}
		if time.Now().After(deadline) {
			return fresh, fmt.Errorf("after %s: want >= %d new child process(es), found %d", timeout, want, len(fresh))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
