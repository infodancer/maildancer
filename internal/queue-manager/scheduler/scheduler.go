// Package scheduler implements the queue scan and retry loop for queue-manager.
package scheduler

import (
	"fmt"
	"log/slog"
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
// and invokes mail-remote for each group.
func (s *Scheduler) processDomainDir(domainPath string) error {
	entries, err := readdir(domainPath)
	if err != nil {
		return err
	}

	// Group envelope filenames by msgid (filename: localpart@msgid.nnn).
	byMsgID := make(map[string][]string)
	for _, name := range entries {
		msgid, ok := extractMsgID(name)
		if !ok {
			continue
		}
		envPath := filepath.Join(domainPath, name)
		if s.isReady(envPath) {
			byMsgID[msgid] = append(byMsgID[msgid], envPath)
		}
	}

	for msgid, envPaths := range byMsgID {
		bodyPath, err := s.resolveBody(envPaths[0], msgid)
		if err != nil {
			slog.Warn("could not resolve body", "msgid", msgid, "error", err)
			continue
		}
		s.invoke(bodyPath, envPaths)
	}
	return nil
}

// isReady returns true if the envelope mtime is old enough for the next attempt.
// Uses a simple exponential backoff: next attempt = mtime + min(2^attempts × 5m, 4h).
// Because we don't store attempt count, we approximate by checking that at least
// the minimum retry interval (5 minutes) has elapsed since the last attempt.
func (s *Scheduler) isReady(envPath string) bool {
	fi, err := os.Stat(envPath)
	if err != nil {
		return false
	}
	// Minimum 5 minutes between attempts. The queue-manager scan interval
	// provides the upper bound; this provides the lower bound.
	return time.Since(fi.ModTime()) >= 5*time.Minute
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
func (s *Scheduler) invoke(bodyPath string, envPaths []string) {
	args := s.buildArgs(bodyPath, envPaths)
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

func (s *Scheduler) buildArgs(bodyPath string, envPaths []string) []string {
	var args []string
	if s.cfg.SmarthostAddr != "" {
		args = append(args, "--smarthost", s.cfg.SmarthostAddr)
	}
	if s.cfg.SmarthostUser != "" {
		args = append(args, "--smarthost-user", s.cfg.SmarthostUser)
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
