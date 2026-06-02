package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusCollector implements the Collector interface using Prometheus metrics.
type PrometheusCollector struct {
	// Outbound queue metrics
	enqueueTotal     *prometheus.CounterVec
	enqueueSizeBytes *prometheus.HistogramVec
	dkimSignsTotal   *prometheus.CounterVec

	// Delivery proxy metrics
	deliveryProxyTotal *prometheus.CounterVec

	// Session lifecycle metrics
	sessionsCreatedTotal prometheus.Counter
	sessionsClosedTotal  prometheus.Counter
	sessionsReapedTotal  prometheus.Counter
}

// NewPrometheusCollector creates a new PrometheusCollector with all metrics registered.
func NewPrometheusCollector(reg prometheus.Registerer) *PrometheusCollector {
	c := &PrometheusCollector{
		enqueueTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_enqueue_total",
			Help: "Total number of outbound enqueue operations.",
		}, []string{"sender_domain", "status"}),
		enqueueSizeBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "session_manager_enqueue_size_bytes",
			Help:    "Size of enqueued messages in bytes.",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 26214400, 52428800},
		}, []string{"sender_domain"}),
		dkimSignsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_dkim_signs_total",
			Help: "Total number of DKIM signing operations.",
		}, []string{"domain", "status"}),

		deliveryProxyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_manager_delivery_proxy_total",
			Help: "Total number of delivery proxy operations.",
		}, []string{"recipient_domain", "status"}),

		sessionsCreatedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_sessions_created_total",
			Help: "Total number of sessions created.",
		}),
		sessionsClosedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_sessions_closed_total",
			Help: "Total number of sessions closed.",
		}),
		sessionsReapedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "session_manager_sessions_reaped_total",
			Help: "Total number of sessions reaped due to idle timeout.",
		}),
	}

	// Register all metrics.
	reg.MustRegister(
		c.enqueueTotal,
		c.enqueueSizeBytes,
		c.dkimSignsTotal,
		c.deliveryProxyTotal,
		c.sessionsCreatedTotal,
		c.sessionsClosedTotal,
		c.sessionsReapedTotal,
	)

	return c
}

// EnqueueCompleted increments the enqueue counter.
func (c *PrometheusCollector) EnqueueCompleted(senderDomain string, status string) {
	c.enqueueTotal.WithLabelValues(senderDomain, status).Inc()
}

// EnqueueSize observes the size of an enqueued message.
func (c *PrometheusCollector) EnqueueSize(senderDomain string, sizeBytes int64) {
	c.enqueueSizeBytes.WithLabelValues(senderDomain).Observe(float64(sizeBytes))
}

// DKIMSignCompleted increments the DKIM signing counter.
func (c *PrometheusCollector) DKIMSignCompleted(domain string, status string) {
	c.dkimSignsTotal.WithLabelValues(domain, status).Inc()
}

// DeliveryProxyCompleted increments the delivery proxy counter.
func (c *PrometheusCollector) DeliveryProxyCompleted(recipientDomain string, status string) {
	c.deliveryProxyTotal.WithLabelValues(recipientDomain, status).Inc()
}

// SessionCreated increments the sessions created counter.
func (c *PrometheusCollector) SessionCreated() {
	c.sessionsCreatedTotal.Inc()
}

// SessionClosed increments the sessions closed counter.
func (c *PrometheusCollector) SessionClosed() {
	c.sessionsClosedTotal.Inc()
}

// SessionReaped increments the sessions reaped counter.
func (c *PrometheusCollector) SessionReaped() {
	c.sessionsReapedTotal.Inc()
}
