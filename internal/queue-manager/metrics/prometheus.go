package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusCollector implements the Collector interface using Prometheus metrics.
type PrometheusCollector struct {
	deliveryAttempts *prometheus.CounterVec
	deliveries       *prometheus.CounterVec
	deliveryDuration *prometheus.HistogramVec
	bouncesGenerated *prometheus.CounterVec
	rateLimitHits    *prometheus.CounterVec
	scanDuration     prometheus.Histogram
	staleRecoveries  prometheus.Counter
	queueDepth       prometheus.Gauge
}

// NewPrometheusCollector creates a new PrometheusCollector with all metrics registered.
func NewPrometheusCollector(reg prometheus.Registerer) *PrometheusCollector {
	c := &PrometheusCollector{
		deliveryAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "queue_delivery_attempts_total",
			Help: "Total number of delivery attempts.",
		}, []string{"domain"}),
		deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "queue_deliveries_total",
			Help: "Total number of deliveries by status.",
		}, []string{"domain", "status"}),
		deliveryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "queue_delivery_duration_seconds",
			Help:    "Duration of delivery attempts in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"domain"}),
		bouncesGenerated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "queue_bounces_generated_total",
			Help: "Total number of DSN bounce messages generated.",
		}, []string{"domain", "reason"}),
		rateLimitHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "queue_rate_limit_hits_total",
			Help: "Total number of rate limit hits per domain.",
		}, []string{"domain"}),
		scanDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "queue_scan_duration_seconds",
			Help:    "Duration of queue scan passes in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		staleRecoveries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "queue_stale_recoveries_total",
			Help: "Total number of stale deliveries recovered after crash.",
		}),
		queueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "queue_depth",
			Help: "Current number of envelopes in the queue.",
		}),
	}

	// Register all metrics
	reg.MustRegister(
		c.deliveryAttempts,
		c.deliveries,
		c.deliveryDuration,
		c.bouncesGenerated,
		c.rateLimitHits,
		c.scanDuration,
		c.staleRecoveries,
		c.queueDepth,
	)

	return c
}

// DeliveryAttempted increments the delivery attempts counter for the domain.
func (c *PrometheusCollector) DeliveryAttempted(recipientDomain string) {
	c.deliveryAttempts.WithLabelValues(recipientDomain).Inc()
}

// DeliveryCompleted increments the delivery counter with the given status.
func (c *PrometheusCollector) DeliveryCompleted(recipientDomain string, status string) {
	c.deliveries.WithLabelValues(recipientDomain, status).Inc()
}

// DeliveryDuration observes the delivery duration for the domain.
func (c *PrometheusCollector) DeliveryDuration(recipientDomain string, duration time.Duration) {
	c.deliveryDuration.WithLabelValues(recipientDomain).Observe(duration.Seconds())
}

// BounceGenerated increments the bounce counter for the domain and reason.
func (c *PrometheusCollector) BounceGenerated(recipientDomain string, reason string) {
	c.bouncesGenerated.WithLabelValues(recipientDomain, reason).Inc()
}

// RateLimitHit increments the rate limit hits counter for the domain.
func (c *PrometheusCollector) RateLimitHit(recipientDomain string) {
	c.rateLimitHits.WithLabelValues(recipientDomain).Inc()
}

// ScanCompleted observes the duration of a queue scan pass.
func (c *PrometheusCollector) ScanCompleted(duration time.Duration) {
	c.scanDuration.Observe(duration.Seconds())
}

// StaleRecovered increments the stale recovery counter.
func (c *PrometheusCollector) StaleRecovered() {
	c.staleRecoveries.Inc()
}

// QueueDepth sets the current queue depth gauge.
func (c *PrometheusCollector) QueueDepth(count int) {
	c.queueDepth.Set(float64(count))
}
