package metrics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
)

// The generic transport and aggregation semantics are covered in
// internal/procmetrics. These tests pin the smtpd-specific contract: smtpd's
// own family definitions survive the child-report round trip, and the smtpd
// parent drops the smtpd-named parent-owned families.

// childReport records events into a private child collector and returns its
// serialized metrics report, exactly as a protocol-handler subprocess ships to
// the parent at exit.
func childReport(t *testing.T, events func(Collector)) []byte {
	t.Helper()
	c, reg := NewHandlerCollector()
	events(c)
	var buf bytes.Buffer
	if err := WriteReport(&buf, reg); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return buf.Bytes()
}

// renderFamily gathers g and returns the text exposition of a single metric
// family, so the aggregate can be compared against what an in-process
// collector would have produced for the same events.
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

func TestSmtpdFamiliesRoundTrip(t *testing.T) {
	child1 := func(c Collector) {
		c.MessageReceived("example.com", 2048)
		c.CommandProcessed("MAIL")
		c.CommandProcessed("RCPT")
		c.RspamdCheckCompleted("sender.test", "ham", 1.5)
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

	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg)
	for _, r := range [][]byte{childReport(t, child1), childReport(t, child2)} {
		if err := pm.Ingest(bytes.NewReader(r)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	for _, name := range []string{
		"smtpd_messages_received_total",
		"smtpd_commands_total",
		"smtpd_messages_size_bytes",
		"smtpd_rspamd_scores",
	} {
		if err := testutil.GatherAndCompare(reg, strings.NewReader(renderFamily(t, refReg, name)), name); err != nil {
			t.Errorf("%s mismatch:\n%v", name, err)
		}
	}
}

func TestSmtpdParentOwnsConnectionFamilies(t *testing.T) {
	// A child reusing the full collector records connection events; the smtpd
	// parent owns those series directly, so ingesting must not double-count
	// them or produce duplicate families on gather.
	report := childReport(t, func(c Collector) {
		c.ConnectionOpened()
		c.TLSConnectionEstablished()
		c.ConnectionClosed()
		c.CommandProcessed("EHLO")
	})

	reg := prometheus.NewRegistry()
	pm := NewParentMetrics(reg)
	pm.ConnectionOpened()
	if err := pm.Ingest(bytes.NewReader(report)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather (duplicate family?): %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "smtpd_connections_total" {
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Errorf("smtpd_connections_total = %v, want 1 (child's copy must be dropped)", got)
			}
		}
	}

	expected := `
# HELP smtpd_tls_connections_total Total number of TLS connections established.
# TYPE smtpd_tls_connections_total counter
smtpd_tls_connections_total 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "smtpd_tls_connections_total"); err != nil {
		t.Errorf("non-owned family from same report did not aggregate:\n%v", err)
	}
}
