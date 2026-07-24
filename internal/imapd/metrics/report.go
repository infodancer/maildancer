package metrics

import (
	"github.com/infodancer/maildancer/internal/procmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

// NewHandlerCollector builds a PrometheusCollector backed by a private registry
// rather than the global default. A protocol-handler subprocess records into it
// for the lifetime of its single IMAP session; at exit the caller hands the
// registry to procmetrics.WriteReport to ship the accumulated series back to
// the dispatcher over the fd-4 report pipe (#188).
//
// Keeping the child on a private registry (instead of DefaultRegisterer) means
// the metric names, labels, and histogram buckets stay defined in exactly one
// place -- NewPrometheusCollector -- shared by both the child recorder and, via
// aggregation, the dispatcher's exposed endpoint.
func NewHandlerCollector() (*PrometheusCollector, *prometheus.Registry) {
	reg := prometheus.NewRegistry()
	return NewPrometheusCollector(reg), reg
}

// ParentMetrics is the imapd dispatcher's metrics surface: parent-owned
// connection lifecycle series plus the aggregate of all protocol-handler
// subprocess reports. The implementation lives in procmetrics.
type ParentMetrics = procmetrics.ParentMetrics

// NewParentMetrics builds the dispatcher metrics surface in the imapd
// namespace and registers it on reg.
func NewParentMetrics(reg prometheus.Registerer) *ParentMetrics {
	return procmetrics.NewParentMetrics(reg, "imapd")
}
