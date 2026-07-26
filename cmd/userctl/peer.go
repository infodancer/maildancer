package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	"github.com/pelletier/go-toml/v2"
)

// peerFilterConfig is a minimal view of the shared config file for reaching
// the same Redis instance and peer policy session-manager uses. The daemon owns
// the full schema; this only needs enough to connect and to honour the
// allowlist.
type peerFilterConfig struct {
	SessionManager struct {
		Redis      config.RedisConfig `toml:"redis"`
		PeerFilter peerfilter.Config  `toml:"peerfilter"`
	} `toml:"session-manager"`
}

// runPeerSubcommand handles `userctl peer list|good|abuse|unban|ban`.
//
// The unban path is not optional garnish: the ban rules are deliberately
// aggressive (a single attempt against a nonexistent account is enough), so an
// operator needs a way to undo a false positive without editing Redis by hand.
func runPeerSubcommand(args []string, configPath string) error {
	if len(args) < 1 {
		return fmt.Errorf("peer: expected `peer list|good|abuse|unban|ban`")
	}

	filter, err := openPeerFilter(configPath)
	if err != nil {
		return err
	}
	if !filter.Enabled() {
		return fmt.Errorf("peer filter is not configured: set session-manager.redis.url " +
			"and session-manager.peerfilter.enabled in the config file")
	}

	ctx := context.Background()

	switch args[0] {
	case "list":
		return runPeerList(ctx, filter, os.Stdout)
	case "good":
		return runPeerGood(ctx, filter, os.Stdout)
	case "abuse":
		return runPeerAbuse(ctx, filter, os.Stdout)
	case "unban":
		return runPeerUnban(ctx, filter, args[1:])
	case "ban":
		return runPeerBan(ctx, filter, args[1:])
	default:
		return fmt.Errorf("peer: unknown action %q (expected list|good|abuse|unban|ban)", args[0])
	}
}

// runPeerAbuse lists the rule-3 abuse counters and, for each, whether a
// threshold is configured.
//
// A signal with no threshold is counted and can never ban: it appears in no ban
// listing and produces no log line, so this is the only place it is visible at
// all. That distinction is the point of the THRESHOLD column -- a counter
// climbing with "none" beside it is a signal being measured before anyone
// decides to enforce it, which is not the same thing as a signal that is broken.
func runPeerAbuse(ctx context.Context, filter *peerfilter.Filter, out io.Writer) error {
	entries, err := filter.ListAbuse(ctx)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "No abuse counters.")
		return nil
	}

	// Closest to its threshold first, then by raw count: those are the addresses
	// about to be banned, or the signals about to need a decision.
	sort.Slice(entries, func(i, j int) bool {
		li, lj := remainingToThreshold(entries[i]), remainingToThreshold(entries[j])
		if li != lj {
			return li < lj
		}
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Prefix < entries[j].Prefix
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tSIGNAL\tCOUNT\tTHRESHOLD\tWINDOW LEFT")
	var counted int
	for _, e := range entries {
		threshold := "none"
		if e.Threshold > 0 {
			threshold = fmt.Sprintf("%d", e.Threshold)
		}
		if e.Threshold <= 0 {
			counted++
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
			e.Prefix, e.Signal, e.Count, threshold, formatTTL(e.TTL))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(out, "\n%d abuse counter(s).\n", len(entries))
	if counted > 0 {
		fmt.Fprintf(out, "%d have no configured threshold: those signals are "+
			"counted only and never ban on their own.\n", counted)
	}
	return nil
}

// remainingToThreshold reports how many more occurrences would ban this peer.
// A signal with no threshold never bans, so it sorts last rather than first.
func remainingToThreshold(e peerfilter.AbuseEntry) int {
	if e.Threshold <= 0 {
		return math.MaxInt
	}
	if remaining := e.Threshold - e.Count; remaining > 0 {
		return remaining
	}
	return 0
}

// runPeerGood lists known-good addresses with both sides of the exemption's
// tradeoff: how many real logins each has, and how many bans its exemption has
// waved through. An address with a nonzero suppressed count is carrying a real
// user *and* hostile traffic, which is the case worth an operator's judgement.
func runPeerGood(ctx context.Context, filter *peerfilter.Filter, out io.Writer) error {
	entries, err := filter.ListGood(ctx)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "No known-good peers.")
		return nil
	}

	// Most suppressed bans first: those are the addresses where the tradeoff is
	// actually being exercised.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SuppressedBans != entries[j].SuppressedBans {
			return entries[i].SuppressedBans > entries[j].SuppressedBans
		}
		return entries[i].Prefix < entries[j].Prefix
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tLOGINS\tBANS SUPPRESSED\tEXPIRES IN")
	var suppressed int
	for _, e := range entries {
		suppressed += e.SuppressedBans
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n",
			e.Prefix, e.SuccessfulAuths, e.SuppressedBans, formatTTL(e.TTL))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(out, "\n%d known-good peer(s), %d ban(s) suppressed.\n",
		len(entries), suppressed)
	if suppressed > 0 {
		fmt.Fprintln(out, "Addresses with suppressed bans carry both a real user "+
			"and hostile traffic.")
	}
	return nil
}

// openPeerFilter builds a Filter from the shared config file.
func openPeerFilter(configPath string) (*peerfilter.Filter, error) {
	if configPath == "" {
		configPath = defaultConfigPath
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}

	var fc peerFilterConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configPath, err)
	}
	if err := fc.SessionManager.PeerFilter.Normalize(); err != nil {
		return nil, err
	}
	if fc.SessionManager.Redis.Password == "" {
		fc.SessionManager.Redis.Password = os.Getenv("REDIS_PASSWORD")
	}

	client, err := fc.SessionManager.Redis.Client()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}

	// Force the filter on for the CLI even if the daemon has it disabled: an
	// operator inspecting or clearing bans should not have to enable
	// enforcement first.
	cfg := fc.SessionManager.PeerFilter
	enabled := true
	cfg.Enabled = &enabled
	return peerfilter.New(cfg, client, slog.Default(), nil)
}

func runPeerList(ctx context.Context, filter *peerfilter.Filter, out io.Writer) error {
	entries, err := filter.List(ctx)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "No active peer bans.")
		return nil
	}

	// Longest remaining ban first: those are the addresses an operator is
	// most likely to be looking for.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].TTL != entries[j].TTL {
			return entries[i].TTL > entries[j].TTL
		}
		return entries[i].Prefix < entries[j].Prefix
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tEXPIRES IN\tSTRIKES\tREASON")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			e.Prefix, formatTTL(e.TTL), e.Strikes, e.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d active ban(s).\n", len(entries))
	return nil
}

func runPeerUnban(ctx context.Context, filter *peerfilter.Filter, args []string) error {
	fs := flag.NewFlagSet("peer unban", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("peer unban: expected one or more addresses")
	}

	for _, ip := range fs.Args() {
		removed, err := filter.Unban(ctx, ip)
		if err != nil {
			return fmt.Errorf("unban %s: %w", ip, err)
		}
		prefix := peerfilter.NormalizePrefix(ip)
		if removed {
			fmt.Printf("unbanned %s (strike history cleared)\n", prefix)
		} else {
			fmt.Printf("%s was not banned (strike history cleared)\n", prefix)
		}
	}
	return nil
}

func runPeerBan(ctx context.Context, filter *peerfilter.Filter, args []string) error {
	fs := flag.NewFlagSet("peer ban", flag.ContinueOnError)
	reason := fs.String("reason", "manual", "reason recorded with the ban")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("peer ban: expected one or more addresses")
	}

	for _, ip := range fs.Args() {
		if filter.Allowed(ip) {
			// Reported rather than silently skipped: the operator asked for
			// something that will not happen, and should know why.
			fmt.Fprintf(os.Stderr, "%s is allowlisted; not banned\n", ip)
			continue
		}
		if err := filter.Ban(ctx, ip, *reason); err != nil {
			return fmt.Errorf("ban %s: %w", ip, err)
		}
		fmt.Printf("banned %s (%s)\n", peerfilter.NormalizePrefix(ip), *reason)
	}
	return nil
}

// formatTTL renders a remaining ban duration compactly. Redis reports no TTL
// for a key set to never expire, which the policy never does -- so an absent
// TTL is worth showing as such rather than as "0s".
func formatTTL(ttl time.Duration) string {
	if ttl <= 0 {
		return "(no expiry)"
	}
	ttl = ttl.Round(time.Second)
	if ttl < time.Hour {
		return ttl.String()
	}
	h := int(ttl.Hours())
	m := int(ttl.Minutes()) % 60
	if h >= 24 {
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
