// Package procmetrics carries per-session metrics from protocol-handler
// subprocesses back to their parent dispatcher, for daemons using the
// fork-per-connection process model (mail-security-model.md, #179).
//
// The child records into a private Prometheus registry for the lifetime of
// its single session and, just before exiting, ships the accumulated metric
// families to the parent over an inherited pipe (WriteReport). The parent
// drains each child's report as it reaps the subprocess and folds it into a
// running aggregate (ParentMetrics.Ingest) exposed on its own /metrics
// endpoint. Connection lifecycle series are the one exception: the parent
// maintains those directly from spawn/reap, because a live gauge cannot be
// summed from ephemeral children.
//
// Extracted from smtpd's implementation (#173) and parameterized by metric
// namespace so smtpd, imapd, and pop3d share one transport (#188). Each
// daemon keeps its own family definitions; this package never needs to know
// them because the report format is self-describing.
package procmetrics

import (
	"errors"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// maxReportBytes bounds how much a protocol-handler subprocess may send to the
// parent in a single metrics report. A report is a handful of pre-aggregated
// counter families plus small histograms, so it comfortably fits well under
// this cap; the cap exists purely so a misbehaving (or compromised) lower-
// privileged child cannot drive unbounded allocation in the privileged parent.
const maxReportBytes = 1 << 16 // 64 KiB

// reportFormat is the wire format for parent<->child metric reports: the
// standard Prometheus protobuf exposition format with length-delimited frames.
// Using expfmt keeps the encoding identical to what Prometheus itself speaks
// and spares us a bespoke framing scheme.
var reportFormat = expfmt.NewFormat(expfmt.TypeProtoDelim)

// ErrEmptyReport is returned by Ingest when the report stream hit EOF with
// zero decoded families. A live handler always gathers at least its plain
// (non-vec) connection counters, so an empty report means the child died
// before writing or was spawned without the report fd (connfork tolerates
// os.Pipe failure by spawning without it). Both were silent before #191:
// the child's exit status is logged at debug and an empty ingest succeeded.
var ErrEmptyReport = errors.New("procmetrics: empty report (handler exited without writing one)")

// WriteReport gathers g and writes its metric families to w as length-delimited
// protobuf. It is called once, just before the protocol-handler subprocess
// exits, with w being the write end of the inherited pipe to the parent.
func WriteReport(w io.Writer, g prometheus.Gatherer) error {
	mfs, err := g.Gather()
	if err != nil {
		return err
	}
	enc := expfmt.NewEncoder(w, reportFormat)
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return err
		}
	}
	return nil
}

// seriesKeySep separates label values in an aggregation key. Label values here
// are domains, protocol verbs, and result strings, none of which contain a NUL
// byte, so this yields a collision-free key.
const seriesKeySep = "\x00"

// aggregator sums metric families reported by protocol-handler subprocesses and
// exposes the running totals as a Prometheus collector. Counters accumulate by
// value; histograms accumulate sample count, sample sum, and per-bucket
// cumulative counts. It is an unchecked collector (Describe sends nothing)
// because the set of families and label combinations is discovered at runtime.
type aggregator struct {
	// parentOwned are families the parent maintains directly from the
	// subprocess lifecycle rather than aggregating from child reports. A
	// live gauge cannot be summed from ephemeral children -- each child's
	// open/close nets to zero, or leaks on crash -- and counting spawns
	// also counts connections whose child died before it could report. The
	// aggregator drops these families if a child includes them (it will:
	// the child reuses the daemon's full collector, whose backend records
	// connection events).
	parentOwned map[string]struct{}

	mu       sync.Mutex
	families map[string]*familyAgg
}

// familyAgg holds the accumulated state for one metric family.
type familyAgg struct {
	help       string
	metricType dto.MetricType
	labelNames []string           // canonical order, taken from the first metric seen
	series     map[string]*series // keyed by label values joined with seriesKeySep
}

// series is one label combination's accumulated value(s).
type series struct {
	labelValues []string
	// counter
	value float64
	// histogram
	sampleCount uint64
	sampleSum   float64
	buckets     map[float64]uint64 // upper bound -> cumulative count
}

func newAggregator(parentOwned map[string]struct{}) *aggregator {
	return &aggregator{
		parentOwned: parentOwned,
		families:    make(map[string]*familyAgg),
	}
}

// ingest decodes a child's length-delimited protobuf report from r and folds it
// into the running totals. r is bounded so a rogue child cannot force unbounded
// allocation in the privileged parent. A decode error leaves already-folded
// families intact and is returned so the caller can count the failure.
func (a *aggregator) ingest(r io.Reader) error {
	dec := expfmt.NewDecoder(io.LimitReader(r, maxReportBytes), reportFormat)

	var mfs []*dto.MetricFamily
	for {
		mf := &dto.MetricFamily{}
		if err := dec.Decode(mf); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		mfs = append(mfs, mf)
	}
	if len(mfs) == 0 {
		return ErrEmptyReport
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for _, mf := range mfs {
		a.mergeFamily(mf)
	}
	return nil
}

// mergeFamily folds one reported family into the aggregate. Caller holds a.mu.
func (a *aggregator) mergeFamily(mf *dto.MetricFamily) {
	name := mf.GetName()
	if _, skip := a.parentOwned[name]; skip {
		return
	}
	switch mf.GetType() {
	case dto.MetricType_COUNTER, dto.MetricType_HISTOGRAM:
	default:
		return // only additive families are aggregated
	}

	fam := a.families[name]
	if fam == nil {
		fam = &familyAgg{
			help:       mf.GetHelp(),
			metricType: mf.GetType(),
			series:     make(map[string]*series),
		}
		a.families[name] = fam
	}

	for _, m := range mf.GetMetric() {
		names, values := splitLabels(m.GetLabel())
		if fam.labelNames == nil {
			fam.labelNames = names
		}
		key := strings.Join(values, seriesKeySep)
		s := fam.series[key]
		if s == nil {
			s = &series{labelValues: values, buckets: make(map[float64]uint64)}
			fam.series[key] = s
		}
		switch fam.metricType {
		case dto.MetricType_COUNTER:
			s.value += m.GetCounter().GetValue()
		case dto.MetricType_HISTOGRAM:
			h := m.GetHistogram()
			s.sampleCount += h.GetSampleCount()
			s.sampleSum += h.GetSampleSum()
			for _, b := range h.GetBucket() {
				s.buckets[b.GetUpperBound()] += b.GetCumulativeCount()
			}
		}
	}
}

// splitLabels returns the label names (sorted, as Gather guarantees) and their
// values in the same order.
func splitLabels(pairs []*dto.LabelPair) (names, values []string) {
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].GetName() < pairs[j].GetName() })
	names = make([]string, len(pairs))
	values = make([]string, len(pairs))
	for i, p := range pairs {
		names[i] = p.GetName()
		values[i] = p.GetValue()
	}
	return names, values
}

// Describe implements prometheus.Collector. The aggregator is unchecked: it
// sends no descriptors because families appear dynamically as children report.
func (a *aggregator) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector, emitting the current totals.
func (a *aggregator) Collect(ch chan<- prometheus.Metric) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for name, fam := range a.families {
		desc := prometheus.NewDesc(name, fam.help, fam.labelNames, nil)
		for _, s := range fam.series {
			switch fam.metricType {
			case dto.MetricType_COUNTER:
				ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, s.value, s.labelValues...)
			case dto.MetricType_HISTOGRAM:
				ch <- prometheus.MustNewConstHistogram(desc, s.sampleCount, s.sampleSum, s.buckets, s.labelValues...)
			}
		}
	}
}

// ParentMetrics is a dispatcher process's metrics surface. It owns the
// connection lifecycle series directly (from spawn/reap) and aggregates
// everything else from protocol-handler subprocess reports. Construct it once
// per process and register it on the process's Prometheus registry.
type ParentMetrics struct {
	connectionsTotal  prometheus.Counter
	connectionsActive prometheus.Gauge
	handlerFailures   *prometheus.CounterVec
	agg               *aggregator
}

// NewParentMetrics builds the parent metrics surface for the given metric
// namespace (the daemon name: "smtpd", "imapd", "pop3d") and registers it on
// reg. The parent-owned families are <namespace>_connections_total and
// <namespace>_connections_active; report ingestion failures are counted in
// <namespace>_handler_failures_total.
func NewParentMetrics(reg prometheus.Registerer, namespace string) *ParentMetrics {
	p := &ParentMetrics{
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: namespace + "_connections_total",
			Help: "Total number of connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: namespace + "_connections_active",
			Help: "Number of currently active connections.",
		}),
		handlerFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: namespace + "_handler_failures_total",
			Help: "Total number of protocol-handler subprocess metrics reports that could not be read or decoded.",
		}, []string{"reason"}),
		agg: newAggregator(map[string]struct{}{
			namespace + "_connections_total":  {},
			namespace + "_connections_active": {},
		}),
	}
	reg.MustRegister(p.connectionsTotal, p.connectionsActive, p.handlerFailures, p.agg)
	return p
}

// ConnectionOpened records a newly spawned protocol-handler.
func (p *ParentMetrics) ConnectionOpened() {
	p.connectionsTotal.Inc()
	p.connectionsActive.Inc()
}

// ConnectionClosed records a reaped protocol-handler. It runs even when the
// child crashed, so the active gauge cannot leak.
func (p *ParentMetrics) ConnectionClosed() {
	p.connectionsActive.Dec()
}

// HandlerFailure counts a child whose metrics report could not be ingested.
func (p *ParentMetrics) HandlerFailure(reason string) {
	p.handlerFailures.WithLabelValues(reason).Inc()
}

// Ingest folds a child's metrics report (read from r) into the aggregate.
func (p *ParentMetrics) Ingest(r io.Reader) error {
	return p.agg.ingest(r)
}

// Sink returns the report sink the dispatchers hand to connfork: it ingests
// the child's report and counts failures by kind -- empty_report for a child
// that exited without writing one, metrics_decode for a malformed report.
// The error is propagated so the caller's reaper can log it.
func (p *ParentMetrics) Sink() func(io.Reader) error {
	return func(r io.Reader) error {
		err := p.Ingest(r)
		switch {
		case err == nil:
		case errors.Is(err, ErrEmptyReport):
			p.HandlerFailure("empty_report")
		default:
			p.HandlerFailure("metrics_decode")
		}
		return err
	}
}
