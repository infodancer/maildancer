package metrics

import (
	"io"

	"github.com/infodancer/maildancer/internal/procmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

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

// WriteReport ships a child registry's accumulated series to the parent over
// the inherited pipe. The transport lives in procmetrics, shared by all
// fork-per-connection daemons (#188).
func WriteReport(w io.Writer, g prometheus.Gatherer) error {
	return procmetrics.WriteReport(w, g)
}

// ParentMetrics is the smtpd parent process's metrics surface: parent-owned
// connection lifecycle series plus the aggregate of all protocol-handler
// subprocess reports. The implementation lives in procmetrics.
type ParentMetrics = procmetrics.ParentMetrics

// NewParentMetrics builds the parent metrics surface in the smtpd namespace
// and registers it on reg.
func NewParentMetrics(reg prometheus.Registerer) *ParentMetrics {
	return procmetrics.NewParentMetrics(reg, "smtpd")
}
