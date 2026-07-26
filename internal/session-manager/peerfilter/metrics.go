package peerfilter

import (
	"strings"

	"github.com/infodancer/maildancer/internal/peersignal"
	"github.com/prometheus/client_golang/prometheus"
)

// Label values that keep an unbounded input bounded. A ban reason or signal
// name that this build does not recognize is counted here rather than becoming
// its own series -- both reach these counters from Redis or from a daemon's
// wire message, so neither is a closed set at runtime even though both are
// closed sets in the source.
const (
	reasonOther = "other"
	signalOther = "other"
)

// Metrics are the peer-filter series. They cover the decisions session-manager
// makes and the dispatchers cannot see: which bans were created and why, which
// abuse signals fired, and how often the known-good exemption waved a ban
// through.
//
// Deliberately no counter for Check verdicts. Every dispatcher already reports
// one via <daemon>_peer_gate_checks_total, and a second family counting the same
// event would be two numbers that disagree the moment one of them has a bug.
//
// A nil *Metrics is safe and does nothing, matching Filter.
type Metrics struct {
	bans         *prometheus.CounterVec
	banStrikes   *prometheus.CounterVec
	abuseSignals *prometheus.CounterVec
	knownGood    prometheus.Counter
	suppressed   prometheus.Counter
	revoked      prometheus.Counter
	unbans       prometheus.Counter
}

// NewMetrics registers the peer-filter series against reg. A nil reg returns
// nil, which every method tolerates: userctl builds a Filter to run one command
// and has no process metrics to contribute to.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		return nil
	}

	m := &Metrics{
		bans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_peer_bans_total",
			Help: "Connection-level peer bans created, by reason class. Rule-3 bans are stored as abuse:<signal> and collapse to \"abuse\" here; the per-signal breakdown is session_manager_peer_abuse_signals_total.",
		}, []string{"reason"}),
		banStrikes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_peer_ban_strikes_total",
			Help: "Peer bans by the offense count on record at the time of the ban. Anything past 2 shares the \"3+\" bucket. A ban at 2 or above served the escalated TTL.",
		}, []string{"strikes"}),
		abuseSignals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_peer_abuse_signals_total",
			Help: "Rule-3 abuse signals recorded, whether or not they reached a ban threshold. A signal with no configured threshold is counted here and never bans, so this is the only place shadowed signals are visible.",
		}, []string{"signal"}),
		knownGood: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_peer_known_good_total",
			Help: "Addresses newly marked known-good by a successful authentication.",
		}),
		suppressed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_peer_ban_suppressed_total",
			Help: "Bans waved through because the address was known-good. A nonzero rate means the exemption is earning its keep; a high one means an address is carrying both a real user and hostile traffic.",
		}),
		revoked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_peer_known_good_revoked_total",
			Help: "Known-good status withdrawn after too many suppressed bans, so the exemption cannot be an indefinite bypass.",
		}),
		unbans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_peer_unbans_total",
			Help: "Bans cleared by an operator with userctl peer unban.",
		}),
	}

	reg.MustRegister(m.bans, m.banStrikes, m.abuseSignals,
		m.knownGood, m.suppressed, m.revoked, m.unbans)

	// Pre-create every label combination so the series exist at zero rather
	// than appearing on first use. An absent counter reads as "not
	// instrumented" and a zero one reads as "nothing happened yet" (#207) --
	// and that difference is the whole question for a shadowed signal, where
	// "never fired" and "never ran" look identical without it.
	for _, reason := range []string{
		ReasonNonexistentAccount, ReasonManual, ReasonAbuse, reasonOther,
	} {
		m.bans.WithLabelValues(reason)
	}
	for _, strikes := range []string{"1", "2", "3+"} {
		m.banStrikes.WithLabelValues(strikes)
	}
	// From peersignal.All rather than a list repeated here: the copy that used
	// to live at this line drifted the moment connection_rate and
	// unhosted_domain were added, and those two are exactly the signals that
	// need a zero series, since neither has a ban threshold.
	for _, signal := range peersignal.All() {
		m.abuseSignals.WithLabelValues(signal)
	}

	return m
}

// banReasonLabel buckets a stored ban reason into a bounded label value.
func banReasonLabel(reason string) string {
	switch {
	case reason == ReasonNonexistentAccount, reason == ReasonManual:
		return reason
	case reason == ReasonAbuse, strings.HasPrefix(reason, ReasonAbuse+":"):
		return ReasonAbuse
	default:
		return reasonOther
	}
}

// strikeLabel buckets an offense count. Strikes are unbounded in Redis, and
// only the escalation boundary is interesting, so everything past it shares a
// bucket.
func strikeLabel(strikes int64) string {
	switch {
	case strikes <= 1:
		// Ban always records at least one strike; a zero here means the strike
		// counter failed and Ban fell back to the base TTL.
		return "1"
	case strikes == 2:
		return "2"
	default:
		return "3+"
	}
}

// signalLabel keeps an unrecognized signal name from growing the label set. A
// daemon from a newer build can report anything.
func signalLabel(signal string) string {
	for _, known := range peersignal.All() {
		if signal == known {
			return signal
		}
	}
	return signalOther
}

// BanRecorded counts a created ban, by reason class and offense count.
func (m *Metrics) BanRecorded(reason string, strikes int64) {
	if m == nil {
		return
	}
	m.bans.WithLabelValues(banReasonLabel(reason)).Inc()
	m.banStrikes.WithLabelValues(strikeLabel(strikes)).Inc()
}

// AbuseSignalRecorded counts a rule-3 signal, whether or not it banned.
func (m *Metrics) AbuseSignalRecorded(signal string) {
	if m == nil {
		return
	}
	m.abuseSignals.WithLabelValues(signalLabel(signal)).Inc()
}

// KnownGoodRecorded counts an address newly marked known-good.
func (m *Metrics) KnownGoodRecorded() {
	if m == nil {
		return
	}
	m.knownGood.Inc()
}

// BanSuppressed counts a ban waved through by the known-good exemption.
func (m *Metrics) BanSuppressed() {
	if m == nil {
		return
	}
	m.suppressed.Inc()
}

// KnownGoodRevoked counts a withdrawal of known-good status.
func (m *Metrics) KnownGoodRevoked() {
	if m == nil {
		return
	}
	m.revoked.Inc()
}

// UnbanRecorded counts an operator-cleared ban.
func (m *Metrics) UnbanRecorded() {
	if m == nil {
		return
	}
	m.unbans.Inc()
}
