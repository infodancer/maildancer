// Package scheduler implements the queue scan and retry loop for queue-manager.
package scheduler

import (
	"bufio"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config holds queue-manager runtime configuration.
type Config struct {
	QueueDir      string
	Binary        string
	SmarthostAddr string
	SmarthostUser string
	Interval      time.Duration
	MessageTTL    time.Duration // default message TTL; used to compute message age for backoff
}

// Scheduler scans the queue and invokes mail-remote for ready envelopes.
type Scheduler struct {
	cfg Config
}

// New creates a Scheduler with the given config.
func New(cfg Config) *Scheduler {
	return &Scheduler{cfg: cfg}
}

// Run loops indefinitely, scanning the queue every cfg.Interval.
func (s *Scheduler) Run() {
	for {
		if err := s.RunOnce(); err != nil {
			slog.Error("queue scan error", "error", err)
		}
		time.Sleep(s.cfg.Interval)
	}
}

// RunOnce performs a single queue scan pass.
func (s *Scheduler) RunOnce() error {
	envDir := filepath.Join(s.cfg.QueueDir, "env")
	return s.scanEnvDir(envDir)
}

// scanEnvDir walks env/{tld}/{domain}/ and groups ready envelopes by body.
func (s *Scheduler) scanEnvDir(envDir string) error {
	tlds, err := readdir(envDir)
	if err != nil {
		return fmt.Errorf("reading env dir %s: %w", envDir, err)
	}

	for _, tld := range tlds {
		tldPath := filepath.Join(envDir, tld)
		domains, err := readdir(tldPath)
		if err != nil {
			slog.Warn("reading tld dir", "path", tldPath, "error", err)
			continue
		}
		for _, domain := range domains {
			domainPath := filepath.Join(tldPath, domain)
			if err := s.processDomainDir(domainPath); err != nil {
				slog.Warn("processing domain dir", "path", domainPath, "error", err)
			}
		}
	}
	return nil
}

// processDomainDir groups all ready envelopes in a domain directory by msgid
// and invokes mail-remote for each group. Expired envelopes get one final
// delivery attempt and are then deleted regardless of outcome.
func (s *Scheduler) processDomainDir(domainPath string) error {
	entries, err := readdir(domainPath)
	if err != nil {
		return err
	}

	// Group envelope filenames by msgid (filename: localpart@msgid.nnn).
	// Track which envelopes are expired for cleanup after delivery.
	type envEntry struct {
		path    string
		expired bool
	}
	byMsgID := make(map[string][]envEntry)

	for _, name := range entries {
		msgid, ok := extractMsgID(name)
		if !ok {
			continue
		}
		envPath := filepath.Join(domainPath, name)
		ttl, err := parseTTL(envPath)
		expired := err == nil && !ttl.IsZero() && time.Now().After(ttl)

		if expired || s.isReady(envPath, ttl) {
			byMsgID[msgid] = append(byMsgID[msgid], envEntry{path: envPath, expired: expired})
		}
	}

	for msgid, entries := range byMsgID {
		bodyPath, err := s.resolveBody(entries[0].path, msgid)
		if err != nil {
			slog.Warn("could not resolve body", "msgid", msgid, "error", err)
			// If we can't find the body, delete expired envelopes anyway —
			// they can never be delivered.
			for _, e := range entries {
				if e.expired {
					slog.Info("removing expired envelope (no body)", "path", e.path)
					if rmErr := os.Remove(e.path); rmErr != nil {
						slog.Warn("could not remove expired envelope", "path", e.path, "error", rmErr)
					}
				}
			}
			continue
		}

		// Split expired envelopes from active ones. Expired envelopes get
		// individual --final invocations so the flag applies only to that
		// single recipient, not the whole batch.
		var activePaths []string
		for _, e := range entries {
			if e.expired {
				s.invoke(bodyPath, []string{e.path}, true)
				slog.Info("removing expired envelope after final attempt", "path", e.path)
				if rmErr := os.Remove(e.path); rmErr != nil && !os.IsNotExist(rmErr) {
					slog.Warn("could not remove expired envelope", "path", e.path, "error", rmErr)
				}
			} else {
				activePaths = append(activePaths, e.path)
			}
		}

		if len(activePaths) > 0 {
			s.invoke(bodyPath, activePaths, false)
		}
	}

	// Clean up orphan body files: bodies whose msgid has no remaining envelopes.
	s.cleanOrphanBodies(domainPath)
	return nil
}

// isReady returns true if the envelope mtime is old enough for the next attempt.
// Uses exponential backoff derived from message age: starts at 5 minutes,
// doubles every hour, caps at 4 hours. Message age is computed from the TTL
// and the configured default message TTL. If TTL is unavailable, falls back to
// the 5-minute minimum interval.
func (s *Scheduler) isReady(envPath string, ttl time.Time) bool {
	fi, err := os.Stat(envPath)
	if err != nil {
		return false
	}
	sinceLastAttempt := time.Since(fi.ModTime())

	if ttl.IsZero() || s.cfg.MessageTTL <= 0 {
		return sinceLastAttempt >= 5*time.Minute
	}
	created := ttl.Add(-s.cfg.MessageTTL)
	age := time.Since(created)
	return sinceLastAttempt >= retryInterval(age)
}

// retryInterval computes the minimum time between delivery attempts based on
// message age. Uses exponential backoff: starts at 5 minutes, doubles every
// hour, caps at 4 hours.
//
//	age 0:    5m
//	age 1h:  10m
//	age 2h:  20m
//	age 3h:  40m
//	age 4h:  80m
//	age 5h+:  4h (capped)
func retryInterval(age time.Duration) time.Duration {
	const (
		base       = 5 * time.Minute
		maxBackoff = 4 * time.Hour
		doubling   = time.Hour
	)
	if age <= 0 {
		return base
	}
	interval := time.Duration(float64(base) * math.Pow(2, float64(age)/float64(doubling)))
	if interval > maxBackoff || interval <= 0 {
		return maxBackoff
	}
	return interval
}

// resolveBody locates the message body file from an envelope path and msgid.
// Envelope path: env/{tld}/{domain}/{localpart}@{msgid}.{n}
// Body path:     msg/{sender-tld}/{sender-domain}/{msgid}
//
// For the initial implementation, the sender domain is encoded in the SENDER
// field of the envelope. Here we do a glob search under msg/ for the msgid,
// which avoids parsing the envelope file just to find the body.
func (s *Scheduler) resolveBody(envPath, msgid string) (string, error) {
	msgDir := filepath.Join(s.cfg.QueueDir, "msg")
	pattern := filepath.Join(msgDir, "*", "*", msgid)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("glob for body %s: %w", msgid, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("body not found for msgid %s", msgid)
	}
	return matches[0], nil
}

// invoke calls mail-remote with the body and envelope paths.
// If final is true, passes --final to signal this is the last delivery attempt.
func (s *Scheduler) invoke(bodyPath string, envPaths []string, final bool) {
	args := s.buildArgs(bodyPath, envPaths, final)
	cmd := exec.Command(s.cfg.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	slog.Info("invoking mail-remote", "body", bodyPath, "envelopes", len(envPaths))
	if err := cmd.Run(); err != nil {
		// mail-remote exits non-zero on temp/perm failure; it handles
		// mtime updates for failed envelopes internally.
		slog.Warn("mail-remote exited with error", "error", err)
	}
}

func (s *Scheduler) buildArgs(bodyPath string, envPaths []string, final bool) []string {
	var args []string
	if s.cfg.SmarthostAddr != "" {
		args = append(args, "--smarthost", s.cfg.SmarthostAddr)
	}
	if s.cfg.SmarthostUser != "" {
		args = append(args, "--smarthost-user", s.cfg.SmarthostUser)
	}
	if final {
		args = append(args, "--final")
	}
	args = append(args, bodyPath)
	args = append(args, envPaths...)
	return args
}

// extractMsgID parses a msgid from an envelope filename: localpart@msgid.nnn
func extractMsgID(name string) (string, bool) {
	at := strings.LastIndex(name, "@")
	if at < 0 {
		return "", false
	}
	rest := name[at+1:] // msgid.nnn
	dot := strings.LastIndex(rest, ".")
	if dot < 0 {
		return "", false
	}
	return rest[:dot], true
}

// parseTTL reads the TTL field from an envelope file without a full parse.
// Returns zero time if the TTL line is missing or unparseable.
func parseTTL(envPath string) (time.Time, error) {
	f, err := os.Open(envPath)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "TTL ") {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(line[4:]))
			if err != nil {
				return time.Time{}, fmt.Errorf("invalid TTL in %s: %w", envPath, err)
			}
			return t, nil
		}
	}
	return time.Time{}, nil
}

// cleanOrphanBodies removes body files under msg/ that have no remaining
// envelopes in any env/ directory. This is called per-domain after processing,
// so it only checks msgids that were seen in this domain directory.
//
// A body is orphaned when all its envelopes have been delivered or expired.
// The scan is cheap: for each msgid body file, glob for any remaining envelopes.
func (s *Scheduler) cleanOrphanBodies(domainPath string) {
	// Re-read the domain directory to see what envelopes remain.
	remaining, err := readdir(domainPath)
	if err != nil {
		return
	}

	// Collect msgids still referenced by at least one envelope.
	activeIDs := make(map[string]bool)
	for _, name := range remaining {
		if msgid, ok := extractMsgID(name); ok {
			activeIDs[msgid] = true
		}
	}

	// Check all body directories for files not referenced by any envelope anywhere.
	msgDir := filepath.Join(s.cfg.QueueDir, "msg")
	tlds, err := readdir(msgDir)
	if err != nil {
		return
	}
	for _, tld := range tlds {
		domains, err := readdir(filepath.Join(msgDir, tld))
		if err != nil {
			continue
		}
		for _, domain := range domains {
			bodies, err := readdir(filepath.Join(msgDir, tld, domain))
			if err != nil {
				continue
			}
			for _, bodyName := range bodies {
				if strings.HasPrefix(bodyName, "tmp_") {
					continue
				}
				if s.bodyHasEnvelopes(bodyName) {
					continue
				}
				bodyPath := filepath.Join(msgDir, tld, domain, bodyName)
				slog.Info("removing orphan body", "path", bodyPath)
				if err := os.Remove(bodyPath); err != nil && !os.IsNotExist(err) {
					slog.Warn("could not remove orphan body", "path", bodyPath, "error", err)
				}
			}
		}
	}
}

// bodyHasEnvelopes checks if any envelope in the queue references this msgid.
func (s *Scheduler) bodyHasEnvelopes(msgid string) bool {
	envDir := filepath.Join(s.cfg.QueueDir, "env")
	// Envelope filename format: {localpart}@{msgid}.{n}
	// Glob for any file containing @{msgid}. in any domain directory.
	pattern := filepath.Join(envDir, "*", "*", "*@"+msgid+".*")
	matches, _ := filepath.Glob(pattern)
	return len(matches) > 0
}

func readdir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
