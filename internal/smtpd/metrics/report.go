package metrics

import (
	"io"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// maxReportBytes bounds how much a protocol-handler subprocess may send to the
// parent in a single metrics report. The report is a handful of pre-aggregated
// counter families plus two small histograms, so it comfortably fits well under
// this cap; the cap exists purely so a misbehaving (or compromised) lower-
// privileged child cannot drive unbounded allocation in the privileged parent.
const maxReportBytes = 1 << 16 // 64 KiB

// reportFormat is the wire format for parent<->child metric reports: the
// standard Prometheus protobuf exposition format with length-delimited frames.
// Using expfmt keeps the encoding identical to what Prometheus itself speaks and
// spares us a bespoke framing scheme.
var reportFormat = expfmt.NewFormat(expfmt.TypeProtoDelim)

// NewHandlerCollector builds a PrometheusCollector backed by a private registry
// rather than the global default. A protocol-handler subprocess records into it
// for the lifetime of its single SMTP session; at exit the caller hands the
// registry to WriteReport to ship the accumulated series back to the parent.
//
// Keeping the child on a private registry (instead of DefaultRegisterer) means
// the metric names, labels, and histogram buckets stay defined in exactly one
// place -- NewPrometheusCollector -- shared by both the child recorder and, via
// aggregation, the parent's exposed endpoint.
func NewHandlerCollector() (*PrometheusCollector, *prometheus.Registry) {
	reg := prometheus.NewRegistry()
	return NewPrometheusCollector(reg), reg
}

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
