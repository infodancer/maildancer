// Package peerfilter holds session-manager's connection-level ban policy for
// hostile peers (#206, docs/hostile-connection-filtering.md).
//
// Ban policy, the Redis client, and the peer keyspace live here and nowhere
// else. The protocol daemons cannot import auth or msgstore (enforced by
// depguard) and must not carry policy of their own, so they ask over the
// SessionService CheckPeer RPC and obey the verdict.
//
// Redis is required. Unlike the authentication rate limiter -- which still has
// per-process value, since a bruteforcer hammering one connection is visible
// to whichever process holds it -- an accept-time ban is worthless without
// shared state: each daemon is a separate process, protocol handlers are
// one-shot subprocesses, and the measured attack sprays several daemons from
// the same addresses. A per-process ban list would let every daemon be sprayed
// independently, so with no Redis configured the filter is disabled outright
// rather than pretending to work.
package peerfilter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis key prefixes. Every key here is written by session-manager only.
const (
	keyBan     = "peer:ban:"
	keyStrikes = "peer:strikes:"
	keyAbuse   = "smtpd:abuse:ip:"
)

// strikeTTL is how long a released ban is remembered for the purpose of
// escalating a repeat offender. Longer than the longest ban, so an address
// that reoffends after serving a full ban is still recognized.
const strikeTTL = 30 * 24 * time.Hour

// Reason labels returned to daemons. Coarse by design: a daemon logs these,
// and they must not reveal which signal fired or which account was named,
// or the verdict becomes a side channel.
const (
	ReasonBanned = "banned"
	ReasonAbuse  = "abuse"
)

// Config is the policy half of the peer filter. The dispatcher half
// (MaxTarpit, GateTimeout, StrictGate) is read by the daemons in phase 3.
type Config struct {
	// Enabled turns the filter on. With Redis unconfigured it has no effect.
	Enabled bool `toml:"enabled"`

	// Allowlist holds CIDRs that are never banned and never checked. This is
	// the escape hatch that keeps a policy bug from locking the operator out
	// of their own mail server, so it is consulted before anything else.
	Allowlist []string `toml:"allowlist"`

	// BanTTL is how long a first-offense ban lasts. Default 24h.
	BanTTL time.Duration `toml:"-"`
	// BanTTLStr is the TOML-friendly form of BanTTL.
	BanTTLStr string `toml:"ban_ttl"`

	// BanTTLRepeat is how long a ban lasts for an address that has been
	// banned before. Default 168h (7 days). Set equal to BanTTL for a flat
	// policy with no escalation.
	BanTTLRepeat time.Duration `toml:"-"`
	// BanTTLRepeatStr is the TOML-friendly form of BanTTLRepeat.
	BanTTLRepeatStr string `toml:"ban_ttl_repeat"`

	// AcceptTarpit is how long a dispatcher should hold a denied connection
	// before closing it. Default 30s. There is no legitimate client behind a
	// banned address and nothing left for it to learn, so holding the socket
	// consumes an attacker connection slot for the price of one descriptor.
	AcceptTarpit time.Duration `toml:"-"`
	// AcceptTarpitStr is the TOML-friendly form of AcceptTarpit.
	AcceptTarpitStr string `toml:"accept_tarpit"`

	// AbuseThresholds maps an abuse signal to the number of occurrences
	// within AbuseWindow that earns a ban. A signal absent from the map is
	// counted but never bans on its own.
	AbuseThresholds map[string]int `toml:"abuse_thresholds"`

	// AbuseWindow is the counting window for abuse signals. Default 1h.
	AbuseWindow time.Duration `toml:"-"`
	// AbuseWindowStr is the TOML-friendly form of AbuseWindow.
	AbuseWindowStr string `toml:"abuse_window"`
}

// Defaults returns the default policy. Deliberately conservative on
// escalation and generous on the tarpit.
func Defaults() Config {
	return Config{
		Enabled:      true,
		Allowlist:    []string{"127.0.0.0/8", "::1/128"},
		BanTTL:       24 * time.Hour,
		BanTTLRepeat: 7 * 24 * time.Hour,
		AcceptTarpit: 30 * time.Second,
		AbuseWindow:  time.Hour,
	}
}

// Normalize parses the duration strings and fills zero values with defaults.
// Call it after unmarshalling TOML.
func (c *Config) Normalize() error {
	d := Defaults()

	for _, f := range []struct {
		name string
		str  string
		dst  *time.Duration
		def  time.Duration
	}{
		{"ban_ttl", c.BanTTLStr, &c.BanTTL, d.BanTTL},
		{"ban_ttl_repeat", c.BanTTLRepeatStr, &c.BanTTLRepeat, d.BanTTLRepeat},
		{"accept_tarpit", c.AcceptTarpitStr, &c.AcceptTarpit, d.AcceptTarpit},
		{"abuse_window", c.AbuseWindowStr, &c.AbuseWindow, d.AbuseWindow},
	} {
		if f.str != "" {
			parsed, err := time.ParseDuration(f.str)
			if err != nil {
				return fmt.Errorf("invalid %s %q: %w", f.name, f.str, err)
			}
			*f.dst = parsed
		}
		if *f.dst == 0 {
			*f.dst = f.def
		}
	}

	// A zero tarpit is a legitimate choice (close immediately), so it is not
	// defaulted away; the loop above cannot express that, hence the explicit
	// check on the string having been set.
	if c.AcceptTarpitStr == "0" || c.AcceptTarpitStr == "0s" {
		c.AcceptTarpit = 0
	}
	return nil
}

// Verdict is the answer to CheckPeer.
type Verdict struct {
	// Banned is true when the dispatcher must not serve this peer.
	Banned bool
	// Tarpit is how long to hold a denied connection before closing it.
	Tarpit time.Duration
	// Reason is a coarse policy label for logs and metrics.
	Reason string
}

// Filter enforces the peer ban policy against Redis.
type Filter struct {
	cfg       Config
	client    *redis.Client
	allowlist []*net.IPNet
	logger    *slog.Logger
}

// New builds a Filter. A nil client, or cfg.Enabled false, returns nil: a nil
// *Filter is safe to use and allows every peer, so callers need no branch.
// Invalid allowlist entries are an error rather than a silent omission -- a
// typo there would remove the operator's own escape hatch.
func New(cfg Config, client *redis.Client, logger *slog.Logger) (*Filter, error) {
	if !cfg.Enabled || client == nil {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	nets := make([]*net.IPNet, 0, len(cfg.Allowlist))
	for _, entry := range cfg.Allowlist {
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist CIDR %q: %w", entry, err)
		}
		nets = append(nets, n)
	}

	return &Filter{cfg: cfg, client: client, allowlist: nets, logger: logger}, nil
}

// Enabled reports whether f will do anything.
func (f *Filter) Enabled() bool { return f != nil }

// Allowed reports whether ip is on the allowlist and therefore exempt from
// every check and every ban.
func (f *Filter) Allowed(ip string) bool {
	if f == nil {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range f.allowlist {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Check reports the verdict for a peer. It fails open: a Redis error allows
// the connection, because a Redis outage must not become a total mail outage.
// The error is logged so the fail-open is visible rather than silent; the
// dispatcher-side metric arrives with phase 3.
func (f *Filter) Check(ctx context.Context, ip string) Verdict {
	if f == nil {
		return Verdict{}
	}
	if f.Allowed(ip) {
		return Verdict{}
	}

	prefix := NormalizePrefix(ip)
	if prefix == "" {
		return Verdict{}
	}

	n, err := f.client.Exists(ctx, keyBan+prefix).Result()
	if err != nil {
		f.logger.Error("peer ban check failed, allowing connection",
			"error", err.Error(), "peer", prefix)
		return Verdict{}
	}
	if n == 0 {
		return Verdict{}
	}
	return Verdict{Banned: true, Tarpit: f.cfg.AcceptTarpit, Reason: ReasonBanned}
}

// Ban bans a peer. reason is recorded as the stored value for the operator's
// benefit; it is not returned to daemons.
//
// The TTL escalates for a repeat offender: an address with a strike already on
// record gets BanTTLRepeat instead of BanTTL. Strikes outlive bans, so an
// address that serves a full ban and comes back is still recognized.
func (f *Filter) Ban(ctx context.Context, ip, reason string) error {
	if f == nil {
		return nil
	}
	if f.Allowed(ip) {
		// Not an error: callers should not have to pre-check, and silently
		// declining is the safe outcome for the operator's own networks.
		f.logger.Info("declining to ban allowlisted peer", "peer", ip, "reason", reason)
		return nil
	}

	prefix := NormalizePrefix(ip)
	if prefix == "" {
		return fmt.Errorf("unparseable peer address %q", ip)
	}

	strikes, err := f.client.Incr(ctx, keyStrikes+prefix).Result()
	if err != nil {
		// Escalation is a refinement, not the point. Ban with the base TTL
		// rather than failing to ban at all.
		f.logger.Warn("strike counter failed; banning with base TTL",
			"error", err.Error(), "peer", prefix)
		strikes = 1
	} else if err := f.client.Expire(ctx, keyStrikes+prefix, strikeTTL).Err(); err != nil {
		f.logger.Warn("strike TTL refresh failed", "error", err.Error(), "peer", prefix)
	}

	ttl := f.cfg.BanTTL
	if strikes > 1 {
		ttl = f.cfg.BanTTLRepeat
	}

	if err := f.client.Set(ctx, keyBan+prefix, reason, ttl).Err(); err != nil {
		return fmt.Errorf("write peer ban: %w", err)
	}
	f.logger.Warn("peer banned",
		"peer", prefix, "reason", reason, "ttl", ttl.String(), "strikes", strikes)
	return nil
}

// Report records an abuse signal and bans the peer when the signal crosses its
// configured threshold. Signals with no configured threshold are counted only.
//
// Errors are returned for the caller to log; the RPC treats them as
// non-fatal, since dropping an abuse count is not worth failing a connection.
func (f *Filter) Report(ctx context.Context, ip, signal string) error {
	if f == nil {
		return nil
	}
	if signal == "" {
		return errors.New("empty abuse signal")
	}
	if f.Allowed(ip) {
		return nil
	}

	prefix := NormalizePrefix(ip)
	if prefix == "" {
		return fmt.Errorf("unparseable peer address %q", ip)
	}

	key := keyAbuse + prefix + ":" + signal
	n, err := f.client.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("increment abuse counter: %w", err)
	}
	if n == 1 {
		// Conditional, matching the auth counters: extending the TTL on every
		// increment would hold the window open forever under a steady trickle.
		if err := f.client.Expire(ctx, key, f.cfg.AbuseWindow).Err(); err != nil {
			f.logger.Warn("abuse counter TTL failed", "error", err.Error(), "key", key)
		}
	}

	threshold, ok := f.cfg.AbuseThresholds[signal]
	if !ok || threshold <= 0 || n < int64(threshold) {
		return nil
	}
	return f.Ban(ctx, ip, ReasonAbuse+":"+signal)
}

// Unban clears a peer's ban and its strike history. Both, deliberately:
// an operator undoing a false positive means it should not count against the
// address later. Reports whether a ban was actually present.
func (f *Filter) Unban(ctx context.Context, ip string) (bool, error) {
	if f == nil {
		return false, nil
	}
	prefix := NormalizePrefix(ip)
	if prefix == "" {
		return false, fmt.Errorf("unparseable peer address %q", ip)
	}

	removed, err := f.client.Del(ctx, keyBan+prefix).Result()
	if err != nil {
		return false, fmt.Errorf("delete peer ban: %w", err)
	}
	if err := f.client.Del(ctx, keyStrikes+prefix).Err(); err != nil {
		return removed > 0, fmt.Errorf("delete peer strikes: %w", err)
	}
	return removed > 0, nil
}

// Ban is one entry in a listing.
type BanEntry struct {
	// Prefix is the banned address or IPv6 /64, as stored.
	Prefix string
	// Reason is the stored policy label.
	Reason string
	// TTL is the remaining ban duration.
	TTL time.Duration
	// Strikes is the offense count on record, 0 if unknown.
	Strikes int
}

// List enumerates the active bans. It uses SCAN rather than KEYS so a large
// ban list does not block Redis for other callers.
func (f *Filter) List(ctx context.Context) ([]BanEntry, error) {
	if f == nil {
		return nil, nil
	}

	var (
		entries []BanEntry
		cursor  uint64
	)
	for {
		keys, next, err := f.client.Scan(ctx, cursor, keyBan+"*", 256).Result()
		if err != nil {
			return nil, fmt.Errorf("scan peer bans: %w", err)
		}
		for _, key := range keys {
			prefix := strings.TrimPrefix(key, keyBan)
			entry := BanEntry{Prefix: prefix}

			if reason, err := f.client.Get(ctx, key).Result(); err == nil {
				entry.Reason = reason
			} else if !errors.Is(err, redis.Nil) {
				return nil, fmt.Errorf("read ban %q: %w", prefix, err)
			}
			if ttl, err := f.client.TTL(ctx, key).Result(); err == nil && ttl > 0 {
				entry.TTL = ttl
			}
			if s, err := f.client.Get(ctx, keyStrikes+prefix).Result(); err == nil {
				if n, convErr := strconv.Atoi(s); convErr == nil {
					entry.Strikes = n
				}
			}
			entries = append(entries, entry)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return entries, nil
}

// NormalizePrefix reduces a peer address to the unit a ban applies to: an IPv4
// address as-is, an IPv6 address to its /64.
//
// Banning single IPv6 addresses is theater -- a /64 is the smallest allocation
// a host is normally given, and cycling addresses inside it is free -- so the
// /64 is the ban unit. Returns "" for an unparseable address.
func NormalizePrefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	masked := parsed.Mask(net.CIDRMask(64, 128))
	if masked == nil {
		return ""
	}
	return masked.String() + "/64"
}
