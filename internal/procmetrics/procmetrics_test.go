package procmetrics

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// testCollector stands in for a daemon's session collector: a labeled counter,
// a histogram, and the connection lifecycle series every daemon's full
// collector also records (which the parent owns and the aggregator must drop).
type testCollector struct {
	commands          *prometheus.CounterVec
	sizes             prometheus.Histogram
	connectionsTotal  prometheus.Counter
	connectionsActive prometheus.Gauge
}

func newTestCollector(reg prometheus.Registerer) *testCollector {
	c := &testCollector{
		commands: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "testd_commands_total",
			Help: "Commands processed.",
		}, []string{"command"}),
		sizes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "testd_messages_size_bytes",
			Help:    "Message sizes.",
			Buckets: []float64{1024, 4096, 16384},
		}),
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "testd_connections_total",
			Help: "Connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "testd_connections_active",
			Help: "Active connections.",
		}),
	}
	reg.MustRegister(c.commands, c.sizes, c.connectionsTotal, c.connectionsActive)
	return c
}

// sessionEvents is a fixed set of collector calls representing one session's
// worth of activity, so a child collector and a reference collector can be fed
// identically.
type sessionEvents func(*testCollector)

// childReport records events into a private child registry and returns its
// serialized metrics report, exactly as a protocol-handler subprocess ships to
// the parent at exit.
func childReport(t *testing.T, events sessionEvents) []byte {
	t.Helper()
	reg := prometheus.NewRegistry()
	events(newTestCollector(reg))
	var buf bytes.Buffer
	if err := WriteReport(&buf, reg); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return buf.Bytes()
}

// renderFamily gathers g and returns the text exposition of a single metric
// family, so tests can assert the aggregator matches what an in-process
// collector would have produced for the same events without hand-formatting
// histogram bucket bounds.
func renderFamily(t *testing.T, g prometheus.Gatherer, name string) string {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather reference: %v", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if mf.GetName() == name {
			if err := enc.Encode(mf); err != nil {
				t.Fatalf("encode reference family %s: %v", name, err)
			}
		}
	}
	return buf.String()
}

// newTestParent builds a ParentMetrics on a fresh registry with the "testd"
// namespace.
func newTestParent(t *testing.T) (*ParentMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	return NewParentMetrics(reg, "testd"), reg
}

func TestAggregatorRoundTripCounters(t *testing.T) {
	child1 := func(c *testCollector) {
		c.commands.WithLabelValues("RETR").Inc()
		c.commands.WithLabelValues("LIST").Inc()
	}
	child2 := func(c *testCollector) {
		c.commands.WithLabelValues("RETR").Inc()
	}

	// Reference: what a single in-process collector would record for both.
	refReg := prometheus.NewRegistry()
	ref := newTestCollector(refReg)
	child1(ref)
	child2(ref)

	pm, reg := newTestParent(t)
	for _, r := range [][]byte{childReport(t, child1), childReport(t, child2)} {
		if err := pm.Ingest(bytes.NewReader(r)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	name := "testd_commands_total"
	if err := testutil.GatherAndCompare(reg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
		t.Errorf("%s mismatch:\n%v", name, err)
	}
}

func TestAggregatorSumsHistogramAcrossChildren(t *testing.T) {
	c1 := func(c *testCollector) { c.sizes.Observe(2048) }
	c2 := func(c *testCollector) { c.sizes.Observe(8192) }

	refReg := prometheus.NewRegistry()
	ref := newTestCollector(refReg)
	c1(ref)
	c2(ref)

	pm, reg := newTestParent(t)
	for _, r := range [][]byte{childReport(t, c1), childReport(t, c2)} {
		if err := pm.Ingest(bytes.NewReader(r)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	name := "testd_messages_size_bytes"
	if err := testutil.GatherAndCompare(reg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
		t.Errorf("%s mismatch:\n%v", name, err)
	}
}

func TestAggregatorSkipsParentOwnedFamilies(t *testing.T) {
	// A child reusing the daemon's full collector records connection events;
	// the parent owns those series directly, so the aggregator must drop them
	// -- and gathering the combined registry must not error on duplicates.
	report := childReport(t, func(c *testCollector) {
		c.connectionsTotal.Inc()
		c.connectionsActive.Inc()
		c.commands.WithLabelValues("QUIT").Inc()
	})

	pm, reg := newTestParent(t)
	pm.ConnectionOpened()
	if err := pm.Ingest(bytes.NewReader(report)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather (duplicate family?): %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "testd_connections_total" {
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Errorf("testd_connections_total = %v, want 1 (parent-owned, child's copy dropped)", got)
			}
		}
	}
	if n := testutil.CollectAndCount(pm.agg, "testd_connections_total"); n != 0 {
		t.Errorf("aggregator emitted %d testd_connections_total series, want 0 (parent-owned)", n)
	}
	if n := testutil.CollectAndCount(pm.agg, "testd_connections_active"); n != 0 {
		t.Errorf("aggregator emitted %d testd_connections_active series, want 0 (parent-owned)", n)
	}
	if n := testutil.CollectAndCount(pm.agg, "testd_commands_total"); n != 1 {
		t.Errorf("testd_commands_total series = %d, want 1", n)
	}
}

func TestAggregatorIngestRejectsGarbage(t *testing.T) {
	pm, _ := newTestParent(t)
	// Seed a valid family so we can confirm garbage leaves state intact.
	if err := pm.Ingest(bytes.NewReader(childReport(t, func(c *testCollector) {
		c.commands.WithLabelValues("STAT").Inc()
	}))); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}

	if err := pm.Ingest(strings.NewReader("this is not a protobuf frame")); err == nil {
		t.Error("ingest(garbage) = nil, want decode error")
	}

	if n := testutil.CollectAndCount(pm.agg, "testd_commands_total"); n != 1 {
		t.Errorf("testd_commands_total series after garbage = %d, want 1 (unchanged)", n)
	}
}

func TestParentMetricsConnectionAccounting(t *testing.T) {
	pm, reg := newTestParent(t)

	pm.ConnectionOpened()
	pm.ConnectionOpened()
	pm.ConnectionClosed()

	if got := gatherValue(t, reg, "testd_connections_total"); got != 2 {
		t.Errorf("testd_connections_total = %v, want 2", got)
	}
	if got := gatherValue(t, reg, "testd_connections_active"); got != 1 {
		t.Errorf("testd_connections_active = %v, want 1", got)
	}
}

func TestParentMetricsHandlerFailure(t *testing.T) {
	pm, reg := newTestParent(t)
	pm.HandlerFailure("metrics_decode")
	pm.HandlerFailure("metrics_decode")

	expected := `
# HELP testd_handler_failures_total Total number of protocol-handler subprocess metrics reports that could not be read or decoded.
# TYPE testd_handler_failures_total counter
testd_handler_failures_total{reason="metrics_decode"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "testd_handler_failures_total"); err != nil {
		t.Errorf("handler failures mismatch:\n%v", err)
	}
}

// TestParentMetricsIngestOverPipe exercises the real fd path the dispatchers
// rely on: a child writes its report to the write end and closes it; the
// parent reads to EOF from the read end and aggregates. Confirms Ingest
// returns at EOF (the child closing its pipe end) rather than blocking, and
// that the series land in the parent registry.
func TestParentMetricsIngestOverPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	report := childReport(t, func(c *testCollector) {
		c.commands.WithLabelValues("RETR").Inc()
		c.sizes.Observe(2048)
	})
	go func() {
		_, _ = w.Write(report)
		_ = w.Close() // child exit closes its end -> parent read sees EOF
	}()

	pm, _ := newTestParent(t)
	if err := pm.Ingest(r); err != nil {
		t.Fatalf("ingest over pipe: %v", err)
	}

	if n := testutil.CollectAndCount(pm.agg, "testd_commands_total"); n != 1 {
		t.Errorf("testd_commands_total series = %d, want 1", n)
	}
	if n := testutil.CollectAndCount(pm.agg, "testd_messages_size_bytes"); n != 1 {
		t.Errorf("testd_messages_size_bytes series = %d, want 1", n)
	}
}

// TestNamespaceIsolation verifies the parent-owned skip set follows the
// namespace: an imapd-named parent must drop imapd_connections_*, not
// smtpd_connections_*.
func TestNamespaceIsolation(t *testing.T) {
	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg, "otherd")

	// Report contains testd connection families -- NOT parent-owned for
	// "otherd", so they aggregate through.
	report := childReport(t, func(c *testCollector) {
		c.connectionsTotal.Inc()
	})
	if err := pm.Ingest(bytes.NewReader(report)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := testutil.CollectAndCount(pm.agg, "testd_connections_total"); n != 1 {
		t.Errorf("foreign-namespace connections family dropped; the skip set must be namespace-scoped")
	}
}

// gatherValue returns the single scalar value of a gauge/counter family with no
// labels from reg.
func gatherValue(t *testing.T, g prometheus.Gatherer, name string) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		metric := mf.GetMetric()
		if len(metric) != 1 {
			t.Fatalf("%s: got %d metrics, want 1", name, len(metric))
		}
		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			return metric[0].GetCounter().GetValue()
		case dto.MetricType_GAUGE:
			return metric[0].GetGauge().GetValue()
		default:
			t.Fatalf("%s: unexpected type %v", name, mf.GetType())
		}
	}
	t.Fatalf("%s: family not found", name)
	return 0
}

// labeledFailureCount returns testd_handler_failures_total{reason=<reason>},
// or 0 when the series does not exist yet.
func labeledFailureCount(t *testing.T, g prometheus.Gatherer, reason string) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "testd_handler_failures_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestIngestEmptyReportIsAnError pins the #191 diagnosis: a report stream
// that hits EOF with zero decoded families means the handler died before
// writing (or never had the report fd) -- a live child always gathers at
// least its plain connection counters. Treating it as success made those
// failures invisible.
func TestIngestEmptyReportIsAnError(t *testing.T) {
	pm, _ := newTestParent(t)
	err := pm.Ingest(bytes.NewReader(nil))
	if !errors.Is(err, ErrEmptyReport) {
		t.Errorf("Ingest(empty) = %v, want ErrEmptyReport", err)
	}
}

// TestSinkClassifiesFailures covers the shared report sink the dispatchers
// hand to connfork: valid reports aggregate cleanly, an empty report counts
// under reason=empty_report, garbage counts under reason=metrics_decode, and
// both propagate the error for the dispatcher's debug log.
func TestSinkClassifiesFailures(t *testing.T) {
	pm, reg := newTestParent(t)
	sink := pm.Sink()

	if err := sink(bytes.NewReader(childReport(t, func(c *testCollector) {
		c.commands.WithLabelValues("STAT").Inc()
	}))); err != nil {
		t.Fatalf("sink(valid report) = %v, want nil", err)
	}
	if got := labeledFailureCount(t, reg, "empty_report"); got != 0 {
		t.Errorf("empty_report after valid ingest = %v, want 0", got)
	}
	if got := labeledFailureCount(t, reg, "metrics_decode"); got != 0 {
		t.Errorf("metrics_decode after valid ingest = %v, want 0", got)
	}

	if err := sink(bytes.NewReader(nil)); !errors.Is(err, ErrEmptyReport) {
		t.Errorf("sink(empty) = %v, want ErrEmptyReport", err)
	}
	if got := labeledFailureCount(t, reg, "empty_report"); got != 1 {
		t.Errorf("empty_report after empty ingest = %v, want 1", got)
	}

	if err := sink(strings.NewReader("this is not a protobuf frame")); err == nil {
		t.Error("sink(garbage) = nil, want decode error")
	}
	if got := labeledFailureCount(t, reg, "metrics_decode"); got != 1 {
		t.Errorf("metrics_decode after garbage ingest = %v, want 1", got)
	}
	if got := labeledFailureCount(t, reg, "empty_report"); got != 1 {
		t.Errorf("empty_report after garbage ingest = %v, want 1 (unchanged)", got)
	}
}
