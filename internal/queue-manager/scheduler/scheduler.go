// Package scheduler implements the queue scan and retry loop for queue-manager.
package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/queue-manager/config"
	"github.com/infodancer/maildancer/internal/queue-manager/delivery"
	"github.com/infodancer/maildancer/internal/queue-manager/dsn"
)

// deliveryResult is the per-recipient outcome reported by mail-remote on stdout.
// The struct mirrors mail-remote's recipientResult JSON output.
type deliveryResult struct {
	Envelope   string `json:"envelope"`
	Status     string `json:"status"`     // "delivered", "perm_fail", "temp_fail"
	SMTPCode   int    `json:"smtp_code"`  // SMTP reply code; 0 if no SMTP response
	Diagnostic string `json:"diagnostic"` // SMTP reply text or error string
}

// Config holds queue-manager runtime configuration.
type Config struct {
	QueueDir         string
	Binary           string
	ConfigPath       string // shared TOML config file; passed as --config to mail-remote
	SmarthostAddr    string // global fallback; used when no per-domain outbound config is found
	SmarthostUser    string // global fallback; used when no per-domain outbound config is found
	DomainConfigPath string // base directory for per-domain config files (enables per-domain outbound routing)
	Interval         time.Duration
	MessageTTL       time.Duration               // default message TTL; used to compute message age for backoff
	Hostname         string                      // reporting MTA hostname for DSN headers
	RateLimit        config.RateLimitConfig      // per-domain delivery rate limiting
	DSN              config.DSNConfig            // DSN bounce generation settings
	SessionManager   config.SessionManagerConfig // session-manager gRPC endpoint
}

// Scheduler scans the queue and invokes mail-remote for ready envelopes.
type Scheduler struct {
	cfg           Config
	limiter       *domainLimiter
	dsnGen        *dsn.Generator   // nil if DSN disabled
	deliverer     *delivery.Client // nil if no session-manager socket configured
	outboundCache map[string]*OutboundConfig
}

// New creates a Scheduler with the given config.
func New(cfg Config) (*Scheduler, error) {
	s := &Scheduler{
		cfg:           cfg,
		limiter:       newDomainLimiter(cfg.RateLimit),
		outboundCache: make(map[string]*OutboundConfig),
	}

	if cfg.DSN.Enabled {
		gen, err := dsn.NewGenerator(cfg.DSN.BounceTemplate)
		if err != nil {
			return nil, fmt.Errorf("creating DSN generator: %w", err)
		}
		s.dsnGen = gen

		if cfg.SessionManager.Socket != "" {
			cl, err := delivery.NewClient("unix://" + cfg.SessionManager.Socket)
			if err != nil {
				return nil, fmt.Errorf("creating session-manager client: %w", err)
			}
			s.deliverer = cl
		}
	}

	return s, nil
}

// Close releases resources held by the scheduler.
func (s *Scheduler) Close() error {
	if s.deliverer != nil {
		return s.deliverer.Close()
	}
	return nil
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
// It first recovers any envelopes left in .delivering state from a previous
// crash, then scans for ready envelopes.
func (s *Scheduler) RunOnce() error {
	s.outboundCache = make(map[string]*OutboundConfig)
	envDir := filepath.Join(s.cfg.QueueDir, "env")
	s.recoverStaleDeliveries(envDir)
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
	// The parsed envelope is cached for DSN generation on permanent failure.
	type envEntry struct {
		path    string
		expired bool
		env     queueEnvelope
	}
	byMsgID := make(map[string][]envEntry)

	for _, name := range entries {
		msgid, ok := extractMsgID(name)
		if !ok {
			continue
		}
		envPath := filepath.Join(domainPath, name)
		env, err := parseEnvelope(envPath)
		if err != nil {
			slog.Warn("could not parse envelope", "path", envPath, "error", err)
			continue
		}
		expired := !env.TTL.IsZero() && time.Now().After(env.TTL)

		if expired || s.isReady(envPath, env.TTL) {
			byMsgID[msgid] = append(byMsgID[msgid], envEntry{path: envPath, expired: expired, env: env})
		}
	}

	fqdn := domainFromPath(domainPath)

	var domainDelivered, domainPermFail, domainTempFail, domainDeferred int

	for msgid, entries := range byMsgID {
		// Check per-domain rate limit before processing this group.
		if s.limiter != nil && !s.limiter.allow(fqdn, len(entries)) {
			slog.Info("rate limited, deferring delivery",
				"domain", fqdn, "msgid", msgid, "envelopes", len(entries))
			domainDeferred += len(entries)
			continue
		}

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

		outbound := s.resolveOutbound(bodyPath)

		// Claim all envelopes atomically before dispatch. If any claim
		// fails (e.g. already .delivering from a concurrent run), skip it.
		type claimedEntry struct {
			original string
			claimed  string
			expired  bool
			env      queueEnvelope
		}
		var claimed []claimedEntry
		for _, e := range entries {
			cp, err := claim(e.path)
			if err != nil {
				slog.Warn("could not claim envelope, skipping", "path", e.path, "error", err)
				continue
			}
			claimed = append(claimed, claimedEntry{original: e.path, claimed: cp, expired: e.expired, env: e.env})
		}

		// Build a map from claimed path to envelope data for DSN generation.
		envByPath := make(map[string]queueEnvelope, len(claimed))
		for _, ce := range claimed {
			envByPath[ce.claimed] = ce.env
		}

		// Split expired envelopes from active ones. Expired envelopes get
		// individual --final invocations so the flag applies only to that
		// single recipient, not the whole batch.
		var activePaths []string
		for _, ce := range claimed {
			if ce.expired {
				results := s.invoke(bodyPath, []string{ce.claimed}, true, outbound)
				tallyResults(results, &domainDelivered, &domainPermFail, &domainTempFail)
				// TTL expiry is a permanent failure for any non-delivered result.
				s.generateDSNsForExpired(bodyPath, results, envByPath, fqdn)
				slog.Info("removing expired envelope after final attempt", "path", ce.claimed)
				if rmErr := os.Remove(ce.claimed); rmErr != nil && !os.IsNotExist(rmErr) {
					slog.Warn("could not remove expired envelope", "path", ce.claimed, "error", rmErr)
				}
			} else {
				activePaths = append(activePaths, ce.claimed)
			}
		}

		if len(activePaths) > 0 {
			results := s.invoke(bodyPath, activePaths, false, outbound)
			tallyResults(results, &domainDelivered, &domainPermFail, &domainTempFail)
			// Mid-queue 5xx: generate DSNs for permanent failures only.
			s.generateDSNsForPermFail(bodyPath, results, envByPath, fqdn)
		}

		// Unclaim surviving envelopes (temp failures — mail-remote touched
		// their mtime but left them on disk).
		for _, p := range activePaths {
			if _, err := os.Stat(p); err != nil {
				continue // already deleted by mail-remote (success or perm fail)
			}
			if _, err := unclaim(p); err != nil {
				slog.Warn("could not unclaim envelope", "path", p, "error", err)
			}
		}
	}

	total := domainDelivered + domainPermFail + domainTempFail + domainDeferred
	if total > 0 {
		slog.Info("domain summary",
			"domain", fqdn,
			"delivered", domainDelivered,
			"perm_fail", domainPermFail,
			"temp_fail", domainTempFail,
			"deferred", domainDeferred)
	}

	// Clean up orphan body files: bodies whose msgid has no remaining envelopes.
	s.cleanOrphanBodies(domainPath)
	return nil
}

// tallyResults counts delivery outcomes from invoke results.
func tallyResults(results []deliveryResult, delivered, permFail, tempFail *int) {
	for _, r := range results {
		switch r.Status {
		case "delivered":
			*delivered++
		case "perm_fail":
			*permFail++
		case "temp_fail":
			*tempFail++
		}
	}
}

// generateDSNsForExpired generates DSN bounce messages for envelopes that
// expired (TTL) and were not delivered on the final attempt. Any non-delivered
// result (perm_fail or temp_fail) at TTL expiry is a permanent failure.
func (s *Scheduler) generateDSNsForExpired(bodyPath string, results []deliveryResult, envByPath map[string]queueEnvelope, domain string) {
	for _, r := range results {
		if r.Status == "delivered" {
			continue
		}
		s.generateAndDeliverDSN(bodyPath, envByPath[r.Envelope], r, domain, true)
	}
}

// generateDSNsForPermFail generates DSN bounce messages for mid-queue
// permanent failures (5xx rejections).
func (s *Scheduler) generateDSNsForPermFail(bodyPath string, results []deliveryResult, envByPath map[string]queueEnvelope, domain string) {
	for _, r := range results {
		if r.Status != "perm_fail" {
			continue
		}
		s.generateAndDeliverDSN(bodyPath, envByPath[r.Envelope], r, domain, false)
	}
}

// generateAndDeliverDSN creates an RFC 3464 DSN bounce message for a failed
// delivery and delivers it to the original sender's local mailbox via
// session-manager. If delivery of the DSN itself fails, it is logged and
// discarded — DSNs are never re-queued (generating a bounce for a bounce
// is an infinite loop).
func (s *Scheduler) generateAndDeliverDSN(bodyPath string, env queueEnvelope, result deliveryResult, domain string, expired bool) {
	if s.dsnGen == nil {
		return
	}

	if env.Origin == "" {
		slog.Warn("skipping DSN: envelope missing origin field",
			"envelope", result.Envelope, "recipient", env.Recipient)
		return
	}

	headers, err := dsn.ExtractHeaders(bodyPath)
	if err != nil {
		slog.Warn("could not read headers for DSN", "body", bodyPath, "error", err)
	}

	data := dsn.BounceData{
		Origin:          env.Origin,
		Recipient:       env.Recipient,
		Domain:          domain,
		SMTPCode:        result.SMTPCode,
		Diagnostic:      result.Diagnostic,
		MessageID:       dsn.ExtractMessageID(headers),
		OriginalHeaders: headers,
		QueuedAt:        env.Created,
		Hostname:        s.cfg.Hostname,
	}
	if expired {
		data.ExpiredAt = env.TTL
	}

	dsnMsg, err := s.dsnGen.Generate(data)
	if err != nil {
		slog.Error("DSN generation failed",
			"origin", env.Origin, "recipient", env.Recipient, "error", err)
		return
	}

	slog.Info("DSN generated",
		"origin", env.Origin, "failed_recipient", env.Recipient, "size", len(dsnMsg))

	if s.deliverer == nil {
		slog.Warn("DSN not delivered: no session-manager configured",
			"origin", env.Origin)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.deliverer.DeliverDSN(ctx, env.Origin, dsnMsg); err != nil {
		slog.Error("DSN delivery failed (discarding)",
			"origin", env.Origin, "failed_recipient", env.Recipient, "error", err)
		return
	}

	slog.Info("DSN delivered",
		"origin", env.Origin, "failed_recipient", env.Recipient)
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

// resolveOutbound determines the outbound transport config for a message
// based on the sender domain extracted from the body path. It checks:
//  1. Per-domain config file ({DomainConfigPath}/{sender}/config.toml)
//  2. System default config ({DomainConfigPath}/config.toml)
//  3. Global CLI fallback (SmarthostAddr/SmarthostUser)
//  4. Direct MX delivery (no smarthost)
//
// Results are cached for the duration of one queue scan pass.
func (s *Scheduler) resolveOutbound(bodyPath string) OutboundConfig {
	if s.cfg.DomainConfigPath == "" {
		return s.globalFallbackOutbound()
	}

	domain := senderDomainFromBodyPath(s.cfg.QueueDir, bodyPath)
	if domain == "" {
		return s.globalFallbackOutbound()
	}

	if cached, ok := s.outboundCache[domain]; ok {
		return *cached
	}

	cfg, err := loadOutboundConfig(s.cfg.DomainConfigPath, domain)
	if err != nil {
		slog.Warn("outbound config load failed, using global fallback",
			"domain", domain, "error", err)
		fb := s.globalFallbackOutbound()
		s.outboundCache[domain] = &fb
		return fb
	}

	// No domain config found — fall back to global CLI flags.
	if cfg == (OutboundConfig{}) {
		fb := s.globalFallbackOutbound()
		s.outboundCache[domain] = &fb
		return fb
	}

	// Default strategy to "direct" when not specified.
	if cfg.Strategy == "" {
		cfg.Strategy = "direct"
	}

	// Read password file if configured.
	if cfg.PasswordFile != "" {
		pw, err := readPasswordFile(s.cfg.DomainConfigPath, domain, cfg)
		if err != nil {
			slog.Warn("could not read password file", "domain", domain, "error", err)
		} else {
			cfg.password = pw
		}
	}

	s.outboundCache[domain] = &cfg
	return cfg
}

// globalFallbackOutbound builds an OutboundConfig from the global CLI flags.
func (s *Scheduler) globalFallbackOutbound() OutboundConfig {
	if s.cfg.SmarthostAddr == "" {
		return OutboundConfig{Strategy: "direct"}
	}
	return OutboundConfig{
		Strategy:      "smarthost",
		Smarthost:     s.cfg.SmarthostAddr,
		SmarthostUser: s.cfg.SmarthostUser,
	}
}

// invoke calls mail-remote with the body and envelope paths, captures
// per-recipient delivery results from stdout, and logs each outcome.
// If final is true, passes --final to signal this is the last delivery attempt.
// The outbound config controls smarthost flags and password passed to the subprocess.
func (s *Scheduler) invoke(bodyPath string, envPaths []string, final bool, outbound OutboundConfig) []deliveryResult {
	args := s.buildArgs(bodyPath, envPaths, final, outbound)
	cmd := exec.Command(s.cfg.Binary, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// Pass per-domain password via subprocess environment.
	if outbound.password != "" {
		cmd.Env = append(cmd.Env, "MAIL_REMOTE_PASSWORD="+outbound.password)
	}

	start := time.Now()
	slog.Info("invoking mail-remote", "body", bodyPath, "envelopes", len(envPaths), "final", final)
	err := cmd.Run()
	duration := time.Since(start)

	if err != nil {
		slog.Warn("mail-remote exited with error", "error", err, "duration", duration)
	}

	var results []deliveryResult
	if stdout.Len() > 0 {
		if jsonErr := json.Unmarshal(stdout.Bytes(), &results); jsonErr != nil {
			slog.Warn("could not parse mail-remote results", "error", jsonErr)
		}
	}

	for _, r := range results {
		switch r.Status {
		case "delivered":
			slog.Info("delivery result",
				"envelope", r.Envelope, "status", r.Status,
				"smtp_code", r.SMTPCode, "duration", duration)
		case "perm_fail":
			slog.Error("delivery result",
				"envelope", r.Envelope, "status", r.Status,
				"smtp_code", r.SMTPCode, "diagnostic", r.Diagnostic,
				"duration", duration)
		case "temp_fail":
			slog.Warn("delivery result",
				"envelope", r.Envelope, "status", r.Status,
				"smtp_code", r.SMTPCode, "diagnostic", r.Diagnostic,
				"duration", duration)
		}
	}

	return results
}

func (s *Scheduler) buildArgs(bodyPath string, envPaths []string, final bool, outbound OutboundConfig) []string {
	var args []string
	if s.cfg.ConfigPath != "" {
		args = append(args, "--config", s.cfg.ConfigPath)
	}
	if outbound.Strategy == "smarthost" && outbound.Smarthost != "" {
		args = append(args, "--smarthost", outbound.Smarthost)
		if outbound.SmarthostUser != "" {
			args = append(args, "--smarthost-user", outbound.SmarthostUser)
		}
	}
	if final {
		args = append(args, "--final")
	}
	args = append(args, bodyPath)
	args = append(args, envPaths...)
	return args
}

// extractMsgID parses a msgid from an envelope filename: localpart@msgid.nnn
// Files with a .delivering suffix are ignored (in-flight envelopes).
func extractMsgID(name string) (string, bool) {
	if strings.HasSuffix(name, deliveringSuffix) {
		return "", false
	}
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

// queueEnvelope is the JSON envelope struct used by queue-manager.
// TTL and Created are used for scheduling; the remaining fields are used
// for DSN bounce generation.
type queueEnvelope struct {
	TTL       time.Time `json:"ttl"`
	Created   time.Time `json:"created"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	MsgID     string    `json:"msgid"`
	Origin    string    `json:"origin"`
}

// parseEnvelope reads and parses a JSON envelope file.
func parseEnvelope(envPath string) (queueEnvelope, error) {
	data, err := os.ReadFile(envPath)
	if err != nil {
		return queueEnvelope{}, err
	}
	var env queueEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return queueEnvelope{}, fmt.Errorf("invalid envelope %s: %w", envPath, err)
	}
	return env, nil
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

// bodyHasEnvelopes checks if any envelope in the queue references this msgid,
// including envelopes currently being delivered (.delivering suffix).
func (s *Scheduler) bodyHasEnvelopes(msgid string) bool {
	envDir := filepath.Join(s.cfg.QueueDir, "env")
	// Envelope filename format: {localpart}@{msgid}.{n} or {localpart}@{msgid}.{n}.delivering
	// Glob for any file containing @{msgid}. in any domain directory.
	pattern := filepath.Join(envDir, "*", "*", "*@"+msgid+".*")
	matches, _ := filepath.Glob(pattern)
	return len(matches) > 0
}

const deliveringSuffix = ".delivering"

// claim atomically renames an envelope file to mark it as in-flight.
// Returns the new path. A concurrent scanner will skip .delivering files
// because extractMsgID won't match the suffix.
func claim(envPath string) (string, error) {
	claimed := envPath + deliveringSuffix
	if err := os.Rename(envPath, claimed); err != nil {
		return "", fmt.Errorf("claim %s: %w", envPath, err)
	}
	return claimed, nil
}

// unclaim renames a .delivering file back to its original name so it
// becomes visible to future scans. os.Rename preserves mtime.
func unclaim(claimedPath string) (string, error) {
	original := strings.TrimSuffix(claimedPath, deliveringSuffix)
	if err := os.Rename(claimedPath, original); err != nil {
		return "", fmt.Errorf("unclaim %s: %w", claimedPath, err)
	}
	return original, nil
}

// recoverStaleDeliveries finds .delivering files left behind by a previous
// crash and renames them back so they become eligible for retry. SMTP
// receivers deduplicate on Message-ID, so a possible re-delivery after
// crash is the correct trade-off versus silent loss.
func (s *Scheduler) recoverStaleDeliveries(envDir string) {
	tlds, err := readdir(envDir)
	if err != nil {
		return
	}
	for _, tld := range tlds {
		domains, err := readdir(filepath.Join(envDir, tld))
		if err != nil {
			continue
		}
		for _, domain := range domains {
			domainPath := filepath.Join(envDir, tld, domain)
			entries, err := readdir(domainPath)
			if err != nil {
				continue
			}
			for _, name := range entries {
				if !strings.HasSuffix(name, deliveringSuffix) {
					continue
				}
				claimedPath := filepath.Join(domainPath, name)
				if _, err := unclaim(claimedPath); err != nil {
					slog.Warn("could not recover stale delivery", "path", claimedPath, "error", err)
				} else {
					slog.Info("recovered stale delivery", "path", claimedPath)
				}
			}
		}
	}
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
