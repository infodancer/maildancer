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

	"github.com/infodancer/maildancer/internal/peersignal"
	"github.com/redis/go-redis/v9"
)

// Redis key prefixes. Every key here is written by session-manager only.
const (
	keyBan        = "peer:ban:"
	keyStrikes    = "peer:strikes:"
	keyAbuse      = "smtpd:abuse:ip:"
	keyGood       = "peer:good:"
	keySuppressed = "peer:suppressed:"
)

// Values for Config.AuthBanScope.
const (
	// AuthBanScopeAuthListeners enforces auth-derived bans only where
	// authentication happens, and shadow-logs them on inbound SMTP.
	AuthBanScopeAuthListeners = "auth_listeners"
	// AuthBanScopeAll enforces auth-derived bans on every listener.
	AuthBanScopeAll = "all"
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

// Stored ban reasons. Unlike the labels above these are internal -- they are the
// value of peer:ban:<prefix> and never cross the wire -- and they carry the
// provenance a ban's scope is derived from (#225).
const (
	// ReasonNonexistentAccount is rule 1: an authentication attempt against an
	// account that does not exist.
	ReasonNonexistentAccount = "nonexistent_account"
	// ReasonManual is an operator ban placed with userctl.
	ReasonManual = "manual"
)

// authDerivedReasons are the stored reasons whose evidence came from the
// authentication path rather than from SMTP behaviour.
//
// The distinction matters because rule 1's justification does not transfer to
// inbound mail. "No legitimate client authenticates as a nonexistent account"
// is airtight; "no legitimate MTA sends from an address that once did" is a
// different and much weaker claim, and acting on it destroys a third party's
// message rather than costing an attacker nothing (#225).
var authDerivedReasons = map[string]bool{
	ReasonNonexistentAccount: true,
}

// isAuthDerived reports whether a stored ban reason came from the auth path.
// Unknown reasons are treated as not auth-derived, so they keep enforcing
// everywhere: a reason nobody has classified should fail toward the stricter
// behaviour, and rule 3's "abuse:<signal>" values land here deliberately.
func isAuthDerived(reason string) bool {
	return authDerivedReasons[reason]
}

// Config is the policy half of the peer filter. The dispatcher half
// (MaxTarpit, GateTimeout, StrictGate) is read by the daemons in phase 3.
type Config struct {
	// Enabled turns the filter on. Absent means enabled: this ships secure by
	// default, and with Redis unconfigured the filter is off regardless, so
	// the default cannot surprise a deployment that has no Redis. A pointer
	// rather than a bool because an absent TOML key and an explicit
	// `enabled = false` must be distinguishable.
	Enabled *bool `toml:"enabled"`

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

	// KnownGood exempts addresses with a recent successful authentication from
	// connection-level bans. Default on.
	//
	// The tradeoff is real and deliberate: a NAT or hosting address can carry
	// both a legitimate user and hostile traffic, and this chooses the user.
	// It is bounded two ways -- see RevokeAfter below, and note that it never
	// exempts the authentication rate limiter, only the connection ban.
	KnownGood *bool `toml:"known_good"`

	// GoodTTL is how long a successful authentication marks an address as
	// known-good. Default 720h (30 days), refreshed on each success.
	//
	// Generous on purpose. A banned address cannot authenticate -- the gate
	// closes the connection first -- so known-good status can only ever be
	// established *before* a ban. Too short a TTL means a real user who is
	// away for a while loses the exemption exactly when a spray from a
	// recycled address would need it.
	GoodTTL time.Duration `toml:"-"`
	// GoodTTLStr is the TOML-friendly form of GoodTTL.
	GoodTTLStr string `toml:"good_ttl"`

	// AuthBanScope controls which listeners an auth-derived ban is enforced on
	// (#225). Two values:
	//
	//   "auth_listeners" (default) -- enforce on the listeners where
	//       authentication is the point (imap, pop3, submission), and only
	//       *record* what would have been refused on inbound SMTP.
	//   "all" -- enforce everywhere, the pre-#225 behaviour.
	//
	// The default is deliberately the narrower one. Refusing an authenticated
	// client's connection costs an attacker nothing; refusing inbound SMTP
	// destroys a third party's message, and rule 1's near-zero false-positive
	// claim is about authentication, not about sending reputation. Shadow mode
	// makes the volume measurable before the stricter setting is chosen.
	//
	// Rule 3 bans (abuse:<signal>) and operator bans are unaffected: their
	// evidence is SMTP-native or deliberate, so they enforce on every listener
	// regardless of this setting.
	AuthBanScope string `toml:"auth_ban_scope"`

	// RevokeAfter is how many suppressed bans an address may accumulate before
	// its known-good status is revoked and bans apply normally. Default 10;
	// negative disables revocation, matching the max_tarpit convention.
	//
	// This is the bound that keeps one compromised credential from buying an
	// indefinite bypass: an address that keeps earning bans stops being
	// trusted, however many real logins it has. Disabling it is a deliberate
	// choice to trust any address a real user has ever authenticated from.
	RevokeAfter int `toml:"revoke_after"`
}

// Defaults returns the default policy. Deliberately conservative on
// escalation and generous on the tarpit.
func Defaults() Config {
	enabled := true
	knownGood := true
	return Config{
		Enabled:      &enabled,
		Allowlist:    []string{"127.0.0.0/8", "::1/128"},
		BanTTL:       24 * time.Hour,
		BanTTLRepeat: 7 * 24 * time.Hour,
		AcceptTarpit: 30 * time.Second,
		AbuseWindow:  time.Hour,
		// Rule 3 thresholds, per AbuseWindow. Conservative because there is no
		// production baseline for either signal yet -- nothing has ever counted
		// them -- so these are set to catch a campaign rather than a stray.
		AbuseThresholds: map[string]int{
			// Legitimate senders do write to retired addresses, and a real MTA
			// retries the same one. Ten distinct-or-repeated misses in an hour
			// is a dictionary, not a typo.
			peersignal.InvalidRecipient: 10,
			// Nothing legitimate asks an unauthenticated relay for a foreign
			// domain, so this could defensibly be 1. Five leaves room for a
			// misconfigured client to fail loudly before being banned.
			peersignal.RelayDenied: 5,
		},
		AuthBanScope: AuthBanScopeAuthListeners,
		KnownGood:    &knownGood,
		GoodTTL:      30 * 24 * time.Hour,
		RevokeAfter:  10,
	}
}

// IsEnabled reports whether the filter should run. Absent configuration means
// enabled.
func (c *Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// KnownGoodEnabled reports whether the known-good exemption applies. Absent
// configuration means enabled.
func (c *Config) KnownGoodEnabled() bool {
	return c.KnownGood == nil || *c.KnownGood
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
		{"good_ttl", c.GoodTTLStr, &c.GoodTTL, d.GoodTTL},
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
	if c.RevokeAfter == 0 {
		c.RevokeAfter = d.RevokeAfter
	}

	// An absent table takes the defaults, so rule 3 enforces without being
	// configured. A table the operator did write is used verbatim, including a
	// deliberately empty one: omitting a signal there is how a signal is turned
	// off, and silently merging defaults back in would make that impossible.
	if c.AbuseThresholds == nil {
		c.AbuseThresholds = d.AbuseThresholds
	}
	switch c.AuthBanScope {
	case "":
		c.AuthBanScope = d.AuthBanScope
	case AuthBanScopeAuthListeners, AuthBanScopeAll:
	default:
		return fmt.Errorf("invalid auth_ban_scope %q (want %q or %q)",
			c.AuthBanScope, AuthBanScopeAuthListeners, AuthBanScopeAll)
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
	// ShadowBanned is true when a ban exists for this peer but is out of scope
	// for the listener that asked (#225). The connection must be served; the
	// dispatcher records what it would have refused so the false-positive cost
	// can be measured before the ban is widened. Never set together with
	// Banned.
	ShadowBanned bool
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
	if !cfg.IsEnabled() || client == nil {
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
func (f *Filter) Check(ctx context.Context, ip string, authFacing bool) Verdict {
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

	// GET rather than EXISTS: the stored value is the ban's reason, and the
	// reason is what the scope decision below is derived from. Same round trip.
	reason, err := f.client.Get(ctx, keyBan+prefix).Result()
	switch {
	case errors.Is(err, redis.Nil):
		return Verdict{} // not banned, the overwhelmingly common case
	case err != nil:
		f.logger.Error("peer ban check failed, allowing connection",
			"error", err.Error(), "peer", prefix)
		return Verdict{}
	}

	// Only a banned address pays for the known-good lookup. Checking it first
	// would add a Redis round trip to every accepted connection, and the
	// overwhelming majority are not banned.
	if f.suppressBan(ctx, prefix) {
		return Verdict{}
	}

	// A ban whose evidence came from the auth path is out of scope for a
	// listener where nobody authenticates (#225). Report it as a shadow ban so
	// the dispatcher serves the connection but records what it would have
	// refused -- the false-positive cost of widening this is a third party's
	// message, so it gets measured before it gets paid.
	if !authFacing && f.cfg.AuthBanScope == AuthBanScopeAuthListeners && isAuthDerived(reason) {
		return Verdict{ShadowBanned: true, Reason: ReasonBanned}
	}

	return Verdict{Banned: true, Tarpit: f.cfg.AcceptTarpit, Reason: ReasonBanned}
}

// suppressBan reports whether prefix's ban should be ignored because a real
// user has authenticated successfully from it recently (#206).
//
// The exemption covers the *connection ban only*. It never touches the
// authentication rate limiter, which lives in auth/domain and keys on the same
// address: a stolen credential buys the attacker connectivity from that
// address, not unlimited password guessing.
//
// Each suppression is counted. Past RevokeAfter the known-good marker is
// dropped and bans apply normally, so an address that keeps earning bans stops
// being trusted however many real logins it has -- the bound that keeps one
// compromised credential from being an indefinite bypass.
func (f *Filter) suppressBan(ctx context.Context, prefix string) bool {
	if !f.cfg.KnownGoodEnabled() {
		return false
	}

	good, err := f.client.Get(ctx, keyGood+prefix).Result()
	switch {
	case errors.Is(err, redis.Nil):
		return false // not known-good; the common case for a banned address
	case err != nil:
		// Fail toward enforcing the ban. The address is banned on evidence;
		// the exemption is a courtesy, and guessing at it during an outage
		// would be the wrong way to fail.
		f.logger.Error("known-good lookup failed, enforcing ban",
			"error", err.Error(), "peer", prefix)
		return false
	}

	suppressed, err := f.client.Incr(ctx, keySuppressed+prefix).Result()
	if err != nil {
		// Losing the count is not worth denying a known-good user, but it does
		// mean revocation cannot progress -- worth a warning.
		f.logger.Warn("suppression counter failed",
			"error", err.Error(), "peer", prefix)
		return true
	}
	if suppressed == 1 {
		if err := f.client.Expire(ctx, keySuppressed+prefix, f.cfg.GoodTTL).Err(); err != nil {
			f.logger.Warn("suppression counter TTL failed",
				"error", err.Error(), "peer", prefix)
		}
	}

	if f.cfg.RevokeAfter > 0 && suppressed > int64(f.cfg.RevokeAfter) {
		if err := f.client.Del(ctx, keyGood+prefix).Err(); err != nil {
			f.logger.Error("known-good revocation failed",
				"error", err.Error(), "peer", prefix)
		}
		f.logger.Warn("known-good status revoked; ban now enforced",
			"peer", prefix,
			"suppressed", suppressed,
			"revoke_after", f.cfg.RevokeAfter,
			"successful_auths", good)
		return false
	}

	// Warn, not info: this is the measurement that makes the tradeoff
	// visible. An address appearing here repeatedly is carrying both a real
	// user and hostile traffic, which is exactly the case worth reviewing.
	f.logger.Warn("ban suppressed for known-good peer",
		"peer", prefix,
		"successful_auths", good,
		"suppressed", suppressed)
	return true
}

// RecordGood notes a successful authentication from ip, marking the address
// known-good for GoodTTL and refreshing the window.
//
// Only real accounts reach this: it is called after session-manager has
// authenticated a user and established a session. Inbound SMTP never
// authenticates, so mail reception cannot mark an address good.
//
// Note the ordering constraint this lives under: a banned address cannot
// authenticate, because the gate closes the connection before any protocol
// runs. Known-good status is therefore only ever established *before* a ban,
// never as a way out of one. Operator recovery for a wrongly banned address is
// `userctl peer unban`.
func (f *Filter) RecordGood(ctx context.Context, ip string) error {
	if f == nil || !f.cfg.KnownGoodEnabled() {
		return nil
	}
	if f.Allowed(ip) {
		return nil // already exempt; nothing to record
	}

	prefix := NormalizePrefix(ip)
	if prefix == "" {
		return fmt.Errorf("unparseable peer address %q", ip)
	}

	n, err := f.client.Incr(ctx, keyGood+prefix).Result()
	if err != nil {
		return fmt.Errorf("record known-good peer: %w", err)
	}
	// Unconditional, unlike the abuse counters: this TTL is a sliding window
	// of trust that every success should extend, not a fixed counting window.
	if err := f.client.Expire(ctx, keyGood+prefix, f.cfg.GoodTTL).Err(); err != nil {
		return fmt.Errorf("refresh known-good TTL: %w", err)
	}
	if n == 1 {
		f.logger.Info("peer marked known-good", "peer", prefix)
	}
	return nil
}

// GoodEntry is one known-good address in a listing.
type GoodEntry struct {
	// Prefix is the address or IPv6 /64, as stored.
	Prefix string
	// SuccessfulAuths is how many successful authentications have come from it
	// within the current window.
	SuccessfulAuths int
	// SuppressedBans is how many bans the exemption has waved through. A
	// nonzero value means this address carries hostile traffic too.
	SuppressedBans int
	// TTL is how long the known-good status has left.
	TTL time.Duration
}

// ListGood enumerates known-good addresses, so both halves of the tradeoff are
// measurable: how many real users the exemption is protecting, and how much
// hostile traffic it is letting through.
func (f *Filter) ListGood(ctx context.Context) ([]GoodEntry, error) {
	if f == nil {
		return nil, nil
	}

	var (
		entries []GoodEntry
		cursor  uint64
	)
	for {
		keys, next, err := f.client.Scan(ctx, cursor, keyGood+"*", 256).Result()
		if err != nil {
			return nil, fmt.Errorf("scan known-good peers: %w", err)
		}
		for _, key := range keys {
			prefix := strings.TrimPrefix(key, keyGood)
			entry := GoodEntry{Prefix: prefix}

			if v, err := f.client.Get(ctx, key).Result(); err == nil {
				if n, convErr := strconv.Atoi(v); convErr == nil {
					entry.SuccessfulAuths = n
				}
			} else if !errors.Is(err, redis.Nil) {
				return nil, fmt.Errorf("read known-good %q: %w", prefix, err)
			}
			if ttl, err := f.client.TTL(ctx, key).Result(); err == nil && ttl > 0 {
				entry.TTL = ttl
			}
			if v, err := f.client.Get(ctx, keySuppressed+prefix).Result(); err == nil {
				if n, convErr := strconv.Atoi(v); convErr == nil {
					entry.SuppressedBans = n
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
	// Strikes and the suppression counter go too, for the same reason: an
	// operator undoing a false positive should not leave the address one strike
	// from a longer ban, nor one suppression from losing its known-good status.
	// The known-good marker itself is left alone -- it records real logins,
	// which an unban does not invalidate.
	if err := f.client.Del(ctx, keyStrikes+prefix, keySuppressed+prefix).Err(); err != nil {
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
