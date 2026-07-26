// Package peergate is the daemon-side client for session-manager's peer ban
// check (#206, docs/hostile-connection-filtering.md).
//
// It implements connfork.PeerGate, so all three protocol dispatchers share one
// implementation of the allowlist, the cache, and the RPC. Policy stays in
// session-manager: this package decides nothing about who is banned, only how
// cheaply the question is answered.
//
// The daemons cannot import auth or msgstore (enforced by depguard), and this
// package does not either -- it speaks the same SessionService gRPC the daemons
// already use for Login and ValidateRecipient.
package peergate

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/peersignal"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
)

// Config is the dispatcher-side half of the peer filter. The policy half
// (ban TTLs, abuse thresholds) belongs to session-manager.
//
// One definition, embedded by each daemon's config under `peergate`, so the
// three cannot drift.
type Config struct {
	// Enabled turns the accept-time gate on. Default true: a deployment that
	// runs session-manager with the filter configured should get enforcement
	// without opting in twice.
	Enabled *bool `toml:"enabled"`

	// Allowlist holds CIDRs never checked and never denied. Consulted before
	// the RPC, so an allowlisted peer costs no round trip. This is the
	// operator's escape hatch: keep the management network here.
	Allowlist []string `toml:"allowlist"`

	// GateTimeout bounds one CheckPeer call. Default 2s.
	GateTimeout time.Duration `toml:"-"`
	// GateTimeoutStr is the TOML-friendly form of GateTimeout.
	GateTimeoutStr string `toml:"gate_timeout"`

	// MaxTarpit caps concurrently held denied connections. Default 256.
	// Negative disables tarpitting: bans are still enforced, but denied
	// connections close immediately.
	MaxTarpit int `toml:"max_tarpit"`

	// StrictGate denies connections when the gate cannot be reached. Off by
	// default -- failing closed turns a session-manager or Redis outage into a
	// refusal of all mail, which is what an attacker wants.
	StrictGate bool `toml:"strict_gate"`

	// AllowTTL is how long an allow verdict is cached. Default 10s. Short: a
	// stale allow is a missed ban for at most this long.
	AllowTTL time.Duration `toml:"-"`
	// AllowTTLStr is the TOML-friendly form of AllowTTL.
	AllowTTLStr string `toml:"allow_ttl"`

	// DenyTTL is how long a deny verdict is cached. Default 60s. Longer than
	// AllowTTL on purpose: a stale deny only over-punishes an address that
	// just earned a ban, and it is what makes a reconnect storm cost one RPC
	// per minute instead of one per connection.
	DenyTTL time.Duration `toml:"-"`
	// DenyTTLStr is the TOML-friendly form of DenyTTL.
	DenyTTLStr string `toml:"deny_ttl"`

	// CacheSize bounds the verdict cache. Default 8192. The cache must be
	// bounded or it becomes its own memory-exhaustion vector under a spray
	// from many source addresses. The connection-rate counter shares this
	// bound: same threat, same magnitude, no reason for a second knob.
	CacheSize int `toml:"cache_size"`

	// ConnRateThreshold is how many accepts from one address, in one listener
	// role, within ConnRateWindow, count as a connection storm. Default 60;
	// negative disables detection, matching MaxTarpit.
	//
	// Crossing it reports a connection_rate abuse signal to session-manager,
	// once per window per address. It does not ban: the signal ships with no
	// configured threshold on the policy side, so it is counted and never
	// enforced until production data says where a threshold belongs (#221). A
	// connection-rate ban is the likeliest false positive in this design -- a
	// legitimately busy sender is the one thing that trips it -- which is why
	// it is measured first.
	ConnRateThreshold int `toml:"connection_rate_threshold"`

	// ConnRateWindow is the counting window for ConnRateThreshold. Default 1m.
	ConnRateWindow time.Duration `toml:"-"`
	// ConnRateWindowStr is the TOML-friendly form of ConnRateWindow.
	ConnRateWindowStr string `toml:"connection_rate_window"`
}

// Dispatcher-side defaults.
const (
	DefaultGateTimeout = 2 * time.Second
	DefaultMaxTarpit   = 256
	DefaultAllowTTL    = 10 * time.Second
	DefaultDenyTTL     = 60 * time.Second
	DefaultCacheSize   = 8192

	// DefaultConnRateThreshold and DefaultConnRateWindow are deliberately
	// generous. The signal never bans yet, so a low threshold would only add
	// noise; the point of the first deployment is to learn what a real busy
	// sender actually does.
	DefaultConnRateThreshold = 60
	DefaultConnRateWindow    = time.Minute
)

// IsEnabled reports whether the gate should run. Absent configuration means
// enabled: this ships secure by default, and a daemon talking to a
// session-manager without the filter configured simply gets allow verdicts.
func (c *Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// Defaults returns a normalized default configuration, for the daemons'
// Default() so that a deployment with no config file still has working
// durations rather than zeros.
func Defaults() Config {
	var c Config
	// Normalize only fails on unparseable duration strings, and there are none.
	_ = c.Normalize()
	return c
}

// Normalize parses duration strings and fills zero values with defaults.
// Call it after unmarshalling TOML.
func (c *Config) Normalize() error {
	for _, f := range []struct {
		name string
		str  string
		dst  *time.Duration
		def  time.Duration
	}{
		{"gate_timeout", c.GateTimeoutStr, &c.GateTimeout, DefaultGateTimeout},
		{"allow_ttl", c.AllowTTLStr, &c.AllowTTL, DefaultAllowTTL},
		{"deny_ttl", c.DenyTTLStr, &c.DenyTTL, DefaultDenyTTL},
		{"connection_rate_window", c.ConnRateWindowStr, &c.ConnRateWindow, DefaultConnRateWindow},
	} {
		if f.str != "" {
			parsed, err := time.ParseDuration(f.str)
			if err != nil {
				return fmt.Errorf("invalid peergate %s %q: %w", f.name, f.str, err)
			}
			*f.dst = parsed
		}
		if *f.dst <= 0 {
			*f.dst = f.def
		}
	}
	if c.MaxTarpit == 0 {
		c.MaxTarpit = DefaultMaxTarpit
	}
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultCacheSize
	}
	// Zero takes the default; negative is preserved because it means disabled.
	if c.ConnRateThreshold == 0 {
		c.ConnRateThreshold = DefaultConnRateThreshold
	}
	return nil
}

// Metrics are optional counters. Any field may be nil.
type Metrics struct {
	// OnCache is called with true on a cache hit, false on a miss.
	OnCache func(hit bool)
	// OnConnRate is called when an address crosses the local connection-rate
	// threshold, with "reported" when the signal was sent to session-manager or
	// "suppressed_banned" when it was not because the peer is already denied.
	OnConnRate func(result string)
}

// Gate answers connfork's accept-time check against session-manager.
type Gate struct {
	cfg       Config
	client    smpb.SessionServiceClient
	allowlist []*net.IPNet
	cache     *verdictCache
	connRate  *connRateCounter
	metrics   Metrics
	logger    *slog.Logger
}

// New builds a Gate over an existing gRPC connection to session-manager.
//
// An invalid allowlist CIDR is an error rather than a dropped entry: silently
// discarding it would remove the operator's escape hatch from a policy bug.
// Returns (nil, nil) when the gate is disabled; a nil *Gate is safe to use and
// allows every peer.
func New(cfg Config, conn grpc.ClientConnInterface, metrics Metrics, logger *slog.Logger) (*Gate, error) {
	if !cfg.IsEnabled() || conn == nil {
		return nil, nil
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	nets := make([]*net.IPNet, 0, len(cfg.Allowlist))
	for _, entry := range cfg.Allowlist {
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid peergate allowlist CIDR %q: %w", entry, err)
		}
		nets = append(nets, n)
	}

	return &Gate{
		cfg:       cfg,
		client:    smpb.NewSessionServiceClient(conn),
		allowlist: nets,
		cache:     newVerdictCache(cfg.CacheSize),
		connRate:  newConnRateCounter(cfg.ConnRateThreshold, cfg.CacheSize, cfg.ConnRateWindow),
		metrics:   metrics,
		logger:    logger,
	}, nil
}

// Enabled reports whether g will do anything.
func (g *Gate) Enabled() bool { return g != nil }

// GateTimeout and the other dispatcher knobs are surfaced so the daemon can
// hand them to connfork without re-reading config.
func (g *Gate) GateTimeout() time.Duration {
	if g == nil {
		return DefaultGateTimeout
	}
	return g.cfg.GateTimeout
}

// MaxTarpit reports the configured tarpit budget.
func (g *Gate) MaxTarpit() int {
	if g == nil {
		return DefaultMaxTarpit
	}
	return g.cfg.MaxTarpit
}

// StrictGate reports whether gate errors should deny.
func (g *Gate) StrictGate() bool {
	if g == nil {
		return false
	}
	return g.cfg.StrictGate
}

// allowed reports whether ip is on the allowlist.
func (g *Gate) allowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.allowlist {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// CheckPeer implements connfork.PeerGate.
//
// Order matters: allowlist first (no RPC at all), then the cache, then the
// call. An error is returned rather than swallowed so connfork can apply its
// own fail-open or strict policy and count the failure.
func (g *Gate) CheckPeer(ctx context.Context, ip string, authFacing bool) (connfork.Verdict, error) {
	if g == nil {
		return connfork.Verdict{}, nil
	}
	if g.allowed(ip) {
		return connfork.Verdict{}, nil
	}

	// The cache key includes the listener role: one dispatcher process serves
	// listeners of both kinds (smtpd owns 25, 465 and 587), and the verdict for
	// an auth-derived ban differs between them (#225). A single-key cache would
	// leak one role's verdict onto the other.
	key := cacheKey(ip, authFacing)

	// Counted before the cache lookup, deliberately: the cache is what hides a
	// reconnect storm from session-manager, so a counter behind it would
	// undercount a flood by exactly the factor that matters. Keyed the same way
	// as the cache, because a submission storm and an inbound-25 storm are
	// different phenomena with different legitimacy, and #225 already showed
	// what unkeyed state shared across roles in one smtpd process does.
	crossed := g.connRate.observe(key)

	if verdict, ok := g.cache.get(key); ok {
		if crossed {
			g.reportConnRate(ip, authFacing, verdict)
		}
		if g.metrics.OnCache != nil {
			g.metrics.OnCache(true)
		}
		return verdict, nil
	}
	if g.metrics.OnCache != nil {
		g.metrics.OnCache(false)
	}

	resp, err := g.client.CheckPeer(ctx, &smpb.CheckPeerRequest{
		Ip:         ip,
		AuthFacing: authFacing,
	})
	if err != nil {
		// Not cached: caching a failure would extend one outage into a
		// cache-TTL-long blind spot.
		return connfork.Verdict{}, fmt.Errorf("check peer: %w", err)
	}

	verdict := connfork.Verdict{
		Banned:       resp.Banned,
		Tarpit:       time.Duration(resp.TarpitMs) * time.Millisecond,
		Reason:       resp.Reason,
		ShadowBanned: resp.ShadowBanned,
	}

	// A shadow ban caches on the deny TTL even though the connection is served:
	// the underlying ban is real, and re-asking every AllowTTL would spend an
	// RPC per connection on exactly the addresses that reconnect most.
	ttl := g.cfg.AllowTTL
	if verdict.Banned || verdict.ShadowBanned {
		ttl = g.cfg.DenyTTL
	}
	g.cache.put(key, verdict, ttl)

	if crossed {
		g.reportConnRate(ip, authFacing, verdict)
	}
	return verdict, nil
}

// reportConnRate sends a connection_rate abuse signal for a peer that crossed
// the local threshold.
//
// Not sent when the peer is already denied. The measurement is still taken --
// the metric records the suppression -- but spending an RPC on an address whose
// connections we are already refusing buys nothing, and once this signal does
// have a ban threshold it would make the ban self-renewing: every ban window's
// reconnect storm would re-cross the threshold and re-ban, turning a 24h ban
// into a permanent one.
//
// Fire-and-forget on its own context. The caller's is cancelled by
// connfork.gateVerdict the instant CheckPeer returns, so reusing it would
// cancel the report before it left. Goroutine count is bounded by the
// once-per-window dedup in the counter.
func (g *Gate) reportConnRate(ip string, authFacing bool, verdict connfork.Verdict) {
	if verdict.Banned || verdict.ShadowBanned {
		if g.metrics.OnConnRate != nil {
			g.metrics.OnConnRate("suppressed_banned")
		}
		return
	}
	if g.metrics.OnConnRate != nil {
		g.metrics.OnConnRate("reported")
	}

	// Warn, not info: like the shadow-ban line, this is the entire dataset for
	// deciding whether the signal should ever enforce. enforced=false is stated
	// in the record so the log says which mode it is in without the reader
	// having to know the config.
	g.logger.Warn("peer crossed the local connection-rate threshold",
		slog.String("client_ip", ip),
		slog.Bool("auth_facing", authFacing),
		slog.Int("threshold", g.cfg.ConnRateThreshold),
		slog.String("window", g.cfg.ConnRateWindow.String()),
		slog.String("signal", peersignal.ConnectionRate),
		slog.Bool("enforced", false))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.cfg.GateTimeout)
		defer cancel()
		if _, err := g.client.ReportPeer(ctx, &smpb.ReportPeerRequest{
			Ip:     ip,
			Signal: peersignal.ConnectionRate,
		}); err != nil {
			// Losing an abuse count is not worth escalating: the signal is
			// volumetric and the next window will report again.
			g.logger.Debug("connection-rate report failed",
				slog.String("client_ip", ip),
				slog.String("error", err.Error()))
		}
	}()
}

// cacheKey scopes a cached verdict to the listener role it was answered for.
func cacheKey(ip string, authFacing bool) string {
	if authFacing {
		return "a:" + ip
	}
	return "i:" + ip
}

// Forget drops any cached verdict for ip, so an operator unban takes effect
// without waiting out DenyTTL. Both listener roles are cleared.
func (g *Gate) Forget(ip string) {
	if g == nil {
		return
	}
	g.cache.forget(cacheKey(ip, true))
	g.cache.forget(cacheKey(ip, false))
}

// verdictCache is a bounded, TTL'd verdict cache.
//
// Eviction is generational rather than LRU: when the live map fills, it becomes
// the previous generation and a fresh map takes over, so lookups check two maps
// and inserts stay O(1). A true LRU would need per-entry bookkeeping on the
// accept path, and scanning for the oldest entry would be O(n) per insert
// exactly when the cache is full -- which under a spray is always.
type verdictCache struct {
	mu   sync.Mutex
	max  int
	cur  map[string]cacheEntry
	prev map[string]cacheEntry
	now  func() time.Time // injectable for tests
}

type cacheEntry struct {
	verdict   connfork.Verdict
	expiresAt time.Time
}

func newVerdictCache(max int) *verdictCache {
	if max <= 0 {
		max = DefaultCacheSize
	}
	return &verdictCache{
		max: max,
		cur: make(map[string]cacheEntry),
		now: time.Now,
	}
}

func (c *verdictCache) get(key string) (connfork.Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, m := range []map[string]cacheEntry{c.cur, c.prev} {
		if m == nil {
			continue
		}
		e, ok := m[key]
		if !ok {
			continue
		}
		if !c.now().Before(e.expiresAt) {
			delete(m, key)
			return connfork.Verdict{}, false
		}
		return e.verdict, true
	}
	return connfork.Verdict{}, false
}

func (c *verdictCache) put(key string, verdict connfork.Verdict, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cur) >= c.max {
		c.prev = c.cur
		c.cur = make(map[string]cacheEntry, c.max/4)
	}
	c.cur[key] = cacheEntry{verdict: verdict, expiresAt: c.now().Add(ttl)}
}

func (c *verdictCache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cur, key)
	if c.prev != nil {
		delete(c.prev, key)
	}
}

// size reports the number of live entries across both generations. Test-only.
func (c *verdictCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.cur)
	if c.prev != nil {
		n += len(c.prev)
	}
	return n
}
