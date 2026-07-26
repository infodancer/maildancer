package peerfilter

import (
	"context"
	"testing"

	"github.com/infodancer/maildancer/internal/peersignal"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// seriesValue returns the value of one series, selected by exact label match.
// Absent series are distinguished from zero-valued ones by the second return:
// that difference is the whole point of #207 and a helper that collapsed it
// would defeat the tests below.
func seriesValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			got := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			if len(got) != len(labels) {
				continue
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if match {
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestMetrics_SeriesExistBeforeAnyEvent is the #207 assertion, and the reason
// this file exists at all. A CounterVec has no series until its first use, so a
// signal that has never fired is indistinguishable from one that is broken --
// which is precisely the question the first production window raised about rule
// 3 ("it never banned" or "it never ran?"). Every label combination must be
// present at zero before anything happens.
func TestMetrics_SeriesExistBeforeAnyEvent(t *testing.T) {
	reg := prometheus.NewRegistry()
	if m := NewMetrics(reg); m == nil {
		t.Fatal("NewMetrics returned nil for a real registry")
	}

	tests := []struct {
		name  string
		want  int
		which string
	}{
		{name: "session_manager_peer_bans_total", want: 4, which: "one per reason bucket"},
		{name: "session_manager_peer_ban_strikes_total", want: 3, which: "one per strike bucket"},
		{name: "session_manager_peer_abuse_signals_total", want: len(peersignal.All()), which: "one per peersignal name"},
		{name: "session_manager_peer_known_good_total", want: 1, which: "unlabelled counter"},
		{name: "session_manager_peer_ban_suppressed_total", want: 1, which: "unlabelled counter"},
		{name: "session_manager_peer_known_good_revoked_total", want: 1, which: "unlabelled counter"},
		{name: "session_manager_peer_unbans_total", want: 1, which: "unlabelled counter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := testutil.GatherAndCount(reg, tt.name)
			if err != nil {
				t.Fatalf("GatherAndCount: %v", err)
			}
			if got != tt.want {
				t.Errorf("%s has %d series, want %d (%s); an absent series reads as \"not instrumented\"",
					tt.name, got, tt.want, tt.which)
			}
		})
	}
}

// TestMetrics_BanReasonBuckets pins the label cardinality decision. The stored
// reason for a rule-3 ban is "abuse:<signal>", which is unbounded as a label
// value, so it collapses to "abuse" -- the per-signal detail already lives in
// peer_abuse_signals_total. An unrecognized reason must land somewhere rather
// than inventing a series.
func TestMetrics_BanReasonBuckets(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{name: "rule 1", reason: ReasonNonexistentAccount, want: ReasonNonexistentAccount},
		{name: "operator", reason: ReasonManual, want: ReasonManual},
		{name: "rule 3 collapses to the bare signal class", reason: ReasonAbuse + ":" + peersignal.RelayDenied, want: ReasonAbuse},
		{name: "another rule 3 signal collapses the same way", reason: ReasonAbuse + ":" + peersignal.InvalidRecipient, want: ReasonAbuse},
		{name: "bare abuse", reason: ReasonAbuse, want: ReasonAbuse},
		{name: "unrecognized", reason: "some_future_reason", want: reasonOther},
		{name: "empty", reason: "", want: reasonOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := banReasonLabel(tt.reason); got != tt.want {
				t.Errorf("banReasonLabel(%q) = %q, want %q", tt.reason, got, tt.want)
			}
		})
	}
}

// TestMetrics_StrikeBuckets keeps the strike label bounded. Strikes are
// unbounded in Redis, so anything past the escalation boundary is one bucket.
func TestMetrics_StrikeBuckets(t *testing.T) {
	tests := []struct {
		name    string
		strikes int64
		want    string
	}{
		{name: "first offense", strikes: 1, want: "1"},
		{name: "second earns the longer TTL", strikes: 2, want: "2"},
		{name: "third", strikes: 3, want: "3+"},
		{name: "persistent offender", strikes: 47, want: "3+"},
		{name: "zero is not a real strike count", strikes: 0, want: "1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strikeLabel(tt.strikes); got != tt.want {
				t.Errorf("strikeLabel(%d) = %q, want %q", tt.strikes, got, tt.want)
			}
		})
	}
}

// TestMetrics_BanIncrementsThroughTheFilter is the wiring test: the counters
// must move when the policy code runs, not only when called directly.
func TestMetrics_BanIncrementsThroughTheFilter(t *testing.T) {
	reg := prometheus.NewRegistry()
	f, _ := newTestFilterWithRegistry(t, reg, nil)
	ctx := context.Background()

	if err := f.Ban(ctx, "203.0.113.5", ReasonNonexistentAccount); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	got, ok := seriesValue(t, reg, "session_manager_peer_bans_total",
		map[string]string{"reason": ReasonNonexistentAccount})
	if !ok {
		t.Fatal("peer_bans_total{reason=nonexistent_account} missing entirely")
	}
	if got != 1 {
		t.Errorf("peer_bans_total = %v, want 1", got)
	}

	if v, _ := seriesValue(t, reg, "session_manager_peer_ban_strikes_total",
		map[string]string{"strikes": "1"}); v != 1 {
		t.Errorf("peer_ban_strikes_total{strikes=\"1\"} = %v, want 1", v)
	}
}

// TestMetrics_AbuseSignalCountedEvenWhenItNeverBans is the shadow-mode
// assertion. A signal with no configured threshold is counted and never bans,
// and the counter is the only way that is observable -- without it, shadow mode
// is indistinguishable from doing nothing.
func TestMetrics_AbuseSignalCountedEvenWhenItNeverBans(t *testing.T) {
	reg := prometheus.NewRegistry()
	f, _ := newTestFilterWithRegistry(t, reg, func(c *Config) {
		// No threshold for this signal at all.
		c.AbuseThresholds = map[string]int{}
	})
	ctx := context.Background()

	for range 50 {
		if err := f.Report(ctx, "203.0.113.5", peersignal.RelayDenied); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}

	if v, ok := seriesValue(t, reg, "session_manager_peer_abuse_signals_total",
		map[string]string{"signal": peersignal.RelayDenied}); !ok || v != 50 {
		t.Errorf("peer_abuse_signals_total{signal=relay_denied} = %v (present=%v), want 50", v, ok)
	}
	// And nothing was banned.
	if v, _ := seriesValue(t, reg, "session_manager_peer_bans_total",
		map[string]string{"reason": ReasonAbuse}); v != 0 {
		t.Errorf("peer_bans_total{reason=abuse} = %v, want 0: an unconfigured signal must not ban", v)
	}
}

// TestMetrics_UnknownSignalIsStillCounted covers a signal name the closed
// peersignal set does not contain -- a daemon reporting something this build
// does not know about. It must be counted rather than dropped, and it must not
// be able to grow the label set without bound.
func TestMetrics_UnknownSignalIsStillCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	f, _ := newTestFilterWithRegistry(t, reg, nil)

	if err := f.Report(context.Background(), "203.0.113.5", "signal_from_the_future"); err != nil {
		t.Fatalf("Report: %v", err)
	}

	if v, ok := seriesValue(t, reg, "session_manager_peer_abuse_signals_total",
		map[string]string{"signal": signalOther}); !ok || v != 1 {
		t.Errorf("peer_abuse_signals_total{signal=%s} = %v (present=%v), want 1", signalOther, v, ok)
	}
}

// TestMetrics_NilRegistryIsSafe covers userctl, which builds a Filter to run
// one command and has no business registering process metrics.
func TestMetrics_NilRegistryIsSafe(t *testing.T) {
	if m := NewMetrics(nil); m != nil {
		t.Fatalf("NewMetrics(nil) = %v, want nil", m)
	}

	// A nil *Metrics must be usable, matching Filter's own nil-safe style.
	var m *Metrics
	m.BanRecorded(ReasonManual, 1)
	m.AbuseSignalRecorded(peersignal.RelayDenied)
	m.KnownGoodRecorded()
	m.BanSuppressed()
	m.KnownGoodRevoked()
	m.UnbanRecorded()

	// And a Filter built without one must work end to end.
	f, _ := newTestFilterWithRegistry(t, nil, nil)
	if err := f.Ban(context.Background(), "203.0.113.5", ReasonManual); err != nil {
		t.Errorf("Ban with no metrics: %v", err)
	}
}

// TestListAbuse_ReportsThresholdAlongsideCount is why ListAbuse exists. A
// signal with no configured threshold never bans, so it appears in no ban
// listing and logs nothing -- the counter in Redis was the only trace, and
// nothing read it. The threshold travels with the count so a listing can say
// which of "measured, deliberately not enforced" and "broken" it is looking at.
func TestListAbuse_ReportsThresholdAlongsideCount(t *testing.T) {
	f, _ := newTestFilter(t, func(c *Config) {
		c.AbuseThresholds = map[string]int{peersignal.RelayDenied: 5}
	})
	ctx := context.Background()

	// One signal with a threshold, one deliberately without.
	for range 3 {
		if err := f.Report(ctx, "203.0.113.5", peersignal.RelayDenied); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}
	for range 7 {
		if err := f.Report(ctx, "203.0.113.5", peersignal.EarlyTalker); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}

	entries, err := f.ListAbuse(ctx)
	if err != nil {
		t.Fatalf("ListAbuse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}

	bySignal := make(map[string]AbuseEntry, len(entries))
	for _, e := range entries {
		bySignal[e.Signal] = e
	}

	if got := bySignal[peersignal.RelayDenied]; got.Count != 3 || got.Threshold != 5 {
		t.Errorf("relay_denied = count %d threshold %d, want 3 and 5", got.Count, got.Threshold)
	}
	// Threshold 0 is the signal that says "counted only, cannot ban".
	if got := bySignal[peersignal.EarlyTalker]; got.Count != 7 || got.Threshold != 0 {
		t.Errorf("early_talker = count %d threshold %d, want 7 and 0", got.Count, got.Threshold)
	}
	for signal, e := range bySignal {
		if e.Prefix != "203.0.113.5" {
			t.Errorf("%s prefix = %q, want the peer address", signal, e.Prefix)
		}
		if e.TTL <= 0 {
			t.Errorf("%s has no window left; the counting window was not set", signal)
		}
	}
}

// TestListAbuse_SplitsIPv6PrefixFromSignal guards the key parse. An IPv6 /64
// prefix contains colons and so does the key separator, so splitting from the
// left would slice the address in half.
func TestListAbuse_SplitsIPv6PrefixFromSignal(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	ctx := context.Background()

	if err := f.Report(ctx, "2001:db8::1", peersignal.RelayDenied); err != nil {
		t.Fatalf("Report: %v", err)
	}

	entries, err := f.ListAbuse(ctx)
	if err != nil {
		t.Fatalf("ListAbuse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Signal != peersignal.RelayDenied {
		t.Errorf("signal = %q, want %q", entries[0].Signal, peersignal.RelayDenied)
	}
	if want := NormalizePrefix("2001:db8::1"); entries[0].Prefix != want {
		t.Errorf("prefix = %q, want %q", entries[0].Prefix, want)
	}
}

// TestListAbuse_EmptyWhenNothingReported keeps the no-data case from looking
// like an error.
func TestListAbuse_EmptyWhenNothingReported(t *testing.T) {
	f, _ := newTestFilter(t, nil)
	entries, err := f.ListAbuse(context.Background())
	if err != nil {
		t.Fatalf("ListAbuse: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %+v, want no entries", entries)
	}
}

// TestDefaults_OmitUnhostedDomain is an intent guard, not a tautology. The
// unhosted-domain signal ships counted-and-never-banning on purpose (#221): the
// benign case is a stale client left pointed at a migrated domain, and the
// previous behaviour -- a first-attempt ban, reached accidentally through the
// fallback agent -- locked out exactly those users. Adding a threshold here
// restores that, so it should be a deliberate act with data behind it rather
// than someone filling in a table.
func TestDefaults_OmitUnhostedDomain(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if n, ok := cfg.AbuseThresholds[peersignal.UnhostedDomain]; ok {
		t.Errorf("unhosted_domain has a default threshold of %d; it must be "+
			"counted only until production data says otherwise", n)
	}
}

// TestMetrics_EveryKnownSignalHasAZeroSeries is the regression guard for a bug
// that reached production. NewMetrics enumerated its signal labels by hand, and
// the list drifted the moment connection_rate and unhosted_domain were added --
// so both shipped with no series until they first fired.
//
// That is the worst case for exactly those two: neither has a ban threshold, so
// they are counted-only, and an absent series is indistinguishable from a signal
// that has never fired, which is the only question anyone will ask of them.
//
// Asserting against peersignal.All rather than a number means adding a constant
// without adding it to All fails here rather than in production.
func TestMetrics_EveryKnownSignalHasAZeroSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewMetrics(reg)

	for _, signal := range peersignal.All() {
		t.Run(signal, func(t *testing.T) {
			if _, ok := seriesValue(t, reg, "session_manager_peer_abuse_signals_total",
				map[string]string{"signal": signal}); !ok {
				t.Errorf("no zero series for %q; a signal that never fired would be "+
					"indistinguishable from one that is broken", signal)
			}
		})
	}
}

// TestMetrics_SignalLabelAcceptsEveryKnownSignal keeps the bucketing in step
// with the same list: a known signal must keep its own label, not be swept into
// "other", or the series pre-created above would stay at zero forever while the
// real traffic landed elsewhere.
func TestMetrics_SignalLabelAcceptsEveryKnownSignal(t *testing.T) {
	for _, signal := range peersignal.All() {
		t.Run(signal, func(t *testing.T) {
			if got := signalLabel(signal); got != signal {
				t.Errorf("signalLabel(%q) = %q, want it preserved", signal, got)
			}
		})
	}
	if got := signalLabel("signal_from_the_future"); got != signalOther {
		t.Errorf("unknown signal = %q, want %q", got, signalOther)
	}
}
