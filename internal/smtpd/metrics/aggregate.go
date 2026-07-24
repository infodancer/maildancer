package metrics

import (
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// parentOwnedFamilies are metric families the parent process maintains directly
// from the subprocess lifecycle (spawn/reap) rather than aggregating from child
// reports. A live gauge cannot be summed from ephemeral children -- each child's
// open/close nets to zero, or leaks on crash -- and counting spawns also counts
// connections whose child died before it could report. The aggregator drops
// these families if a child includes them (it will: the child reuses the full
// PrometheusCollector, whose backend records connection events).
var parentOwnedFamilies = map[string]struct{}{
	"smtpd_connections_total":  {},
	"smtpd_connections_active": {},
}

// seriesKeySep separates label values in an aggregation key. Label values here
// are domains, SMTP verbs, and result strings, none of which contain a NUL
// byte, so this yields a collision-free key.
const seriesKeySep = "\x00"

// aggregator sums metric families reported by protocol-handler subprocesses and
// exposes the running totals as a Prometheus collector. Counters accumulate by
// value; histograms accumulate sample count, sample sum, and per-bucket
// cumulative counts. It is an unchecked collector (Describe sends nothing)
// because the set of families and label combinations is discovered at runtime.
type aggregator struct {
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

func newAggregator() *aggregator {
	return &aggregator{families: make(map[string]*familyAgg)}
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
	if _, skip := parentOwnedFamilies[name]; skip {
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

// ParentMetrics is the smtpd parent process's metrics surface. It owns the
// connection lifecycle series directly (from spawn/reap) and aggregates
// everything else from protocol-handler subprocess reports. Construct it once
// and register it on the process's Prometheus registry.
type ParentMetrics struct {
	connectionsTotal  prometheus.Counter
	connectionsActive prometheus.Gauge
	handlerFailures   *prometheus.CounterVec
	agg               *aggregator
}

// NewParentMetrics builds the parent metrics surface and registers it on reg.
func NewParentMetrics(reg prometheus.Registerer) *ParentMetrics {
	p := &ParentMetrics{
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "smtpd_connections_total",
			Help: "Total number of SMTP connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "smtpd_connections_active",
			Help: "Number of currently active SMTP connections.",
		}),
		handlerFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_handler_failures_total",
			Help: "Total number of protocol-handler subprocess metrics reports that could not be read or decoded.",
		}, []string{"reason"}),
		agg: newAggregator(),
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
