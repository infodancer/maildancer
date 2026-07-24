package metrics

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// sessionEvents is a fixed set of collector calls representing one SMTP
// session's worth of activity, so a child collector and a reference collector
// can be fed identically.
type sessionEvents func(Collector)

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

// childReport records events into a private child collector and returns its
// serialized metrics report, exactly as a protocol-handler subprocess ships to
// the parent at exit.
func childReport(t *testing.T, events sessionEvents) []byte {
	t.Helper()
	c, reg := NewHandlerCollector()
	events(c)
	var buf bytes.Buffer
	if err := WriteReport(&buf, reg); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return buf.Bytes()
}

func TestAggregatorRoundTripCounters(t *testing.T) {
	child1 := func(c Collector) {
		c.MessageReceived("example.com", 2048)
		c.CommandProcessed("MAIL")
		c.CommandProcessed("RCPT")
	}
	child2 := func(c Collector) {
		c.MessageReceived("example.com", 4096)
		c.MessageReceived("other.net", 100)
		c.CommandProcessed("MAIL")
	}

	// Reference: what a single in-process collector would record for both.
	refReg := prometheus.NewRegistry()
	ref := NewPrometheusCollector(refReg)
	child1(ref)
	child2(ref)

	agg := newAggregator()
	for _, r := range [][]byte{childReport(t, child1), childReport(t, child2)} {
		if err := agg.ingest(bytes.NewReader(r)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	for _, name := range []string{"smtpd_messages_received_total", "smtpd_commands_total"} {
		if err := testutil.CollectAndCompare(agg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
			t.Errorf("%s mismatch:\n%v", name, err)
		}
	}
}

func TestAggregatorRoundTripHistogram(t *testing.T) {
	events := func(c Collector) {
		c.MessageReceived("example.com", 2048)
		c.MessageReceived("example.com", 4096)
		c.RspamdCheckCompleted("sender.test", "ham", 1.5)
	}

	refReg := prometheus.NewRegistry()
	ref := NewPrometheusCollector(refReg)
	events(ref)

	agg := newAggregator()
	if err := agg.ingest(bytes.NewReader(childReport(t, events))); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	for _, name := range []string{"smtpd_messages_size_bytes", "smtpd_rspamd_scores"} {
		if err := testutil.CollectAndCompare(agg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
			t.Errorf("%s mismatch:\n%v", name, err)
		}
	}
}

func TestAggregatorSumsHistogramAcrossChildren(t *testing.T) {
	c1 := func(c Collector) { c.MessageReceived("example.com", 2048) }
	c2 := func(c Collector) { c.MessageReceived("example.com", 4096) }

	refReg := prometheus.NewRegistry()
	ref := NewPrometheusCollector(refReg)
	c1(ref)
	c2(ref)

	agg := newAggregator()
	for _, r := range [][]byte{childReport(t, c1), childReport(t, c2)} {
		if err := agg.ingest(bytes.NewReader(r)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	name := "smtpd_messages_size_bytes"
	if err := testutil.CollectAndCompare(agg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
		t.Errorf("%s mismatch:\n%v", name, err)
	}
}

func TestAggregatorSkipsParentOwnedFamilies(t *testing.T) {
	// A child reusing the full collector records connection events; the parent
	// owns those series directly, so the aggregator must drop them.
	report := childReport(t, func(c Collector) {
		c.ConnectionOpened()
		c.TLSConnectionEstablished()
		c.ConnectionClosed()
		c.CommandProcessed("EHLO")
	})

	agg := newAggregator()
	if err := agg.ingest(bytes.NewReader(report)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if n := testutil.CollectAndCount(agg, "smtpd_connections_total"); n != 0 {
		t.Errorf("smtpd_connections_total series = %d, want 0 (parent-owned)", n)
	}
	if n := testutil.CollectAndCount(agg, "smtpd_connections_active"); n != 0 {
		t.Errorf("smtpd_connections_active series = %d, want 0 (parent-owned)", n)
	}
	// A non-owned family from the same report still comes through.
	if n := testutil.CollectAndCount(agg, "smtpd_tls_connections_total"); n != 1 {
		t.Errorf("smtpd_tls_connections_total series = %d, want 1", n)
	}
	if n := testutil.CollectAndCount(agg, "smtpd_commands_total"); n != 1 {
		t.Errorf("smtpd_commands_total series = %d, want 1", n)
	}
}

func TestAggregatorIngestRejectsGarbage(t *testing.T) {
	agg := newAggregator()
	// Seed a valid family so we can confirm garbage leaves state intact.
	if err := agg.ingest(bytes.NewReader(childReport(t, func(c Collector) {
		c.CommandProcessed("MAIL")
	}))); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}

	if err := agg.ingest(strings.NewReader("this is not a protobuf frame")); err == nil {
		t.Error("ingest(garbage) = nil, want decode error")
	}

	if n := testutil.CollectAndCount(agg, "smtpd_commands_total"); n != 1 {
		t.Errorf("smtpd_commands_total series after garbage = %d, want 1 (unchanged)", n)
	}
}

func TestParentMetricsConnectionAccounting(t *testing.T) {
	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg)

	pm.ConnectionOpened()
	pm.ConnectionOpened()
	pm.ConnectionClosed()

	if got := gatherValue(t, reg, "smtpd_connections_total"); got != 2 {
		t.Errorf("smtpd_connections_total = %v, want 2", got)
	}
	if got := gatherValue(t, reg, "smtpd_connections_active"); got != 1 {
		t.Errorf("smtpd_connections_active = %v, want 1", got)
	}
}

func TestParentMetricsHandlerFailure(t *testing.T) {
	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg)
	pm.HandlerFailure("metrics_decode")
	pm.HandlerFailure("metrics_decode")

	expected := `
# HELP smtpd_handler_failures_total Total number of protocol-handler subprocess metrics reports that could not be read or decoded.
# TYPE smtpd_handler_failures_total counter
smtpd_handler_failures_total{reason="metrics_decode"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "smtpd_handler_failures_total"); err != nil {
		t.Errorf("handler failures mismatch:\n%v", err)
	}
}

// TestParentMetricsIngestOverPipe exercises the real fd path spawnHandler
// relies on: a child writes its report to the write end and closes it; the
// parent reads to EOF from the read end and aggregates. Confirms Ingest returns
// at EOF (the child closing fd 4) rather than blocking, and that the series land
// in the parent registry.
func TestParentMetricsIngestOverPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	report := childReport(t, func(c Collector) {
		c.CommandProcessed("MAIL")
		c.MessageReceived("example.com", 2048)
	})
	go func() {
		_, _ = w.Write(report)
		_ = w.Close() // child exit closes fd 4 -> parent read sees EOF
	}()

	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg)
	if err := pm.Ingest(r); err != nil {
		t.Fatalf("ingest over pipe: %v", err)
	}

	if n := testutil.CollectAndCount(pm.agg, "smtpd_commands_total"); n != 1 {
		t.Errorf("smtpd_commands_total series = %d, want 1", n)
	}
	if n := testutil.CollectAndCount(pm.agg, "smtpd_messages_received_total"); n != 1 {
		t.Errorf("smtpd_messages_received_total series = %d, want 1", n)
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
