package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusCollector implements the Collector interface using Prometheus metrics.
type PrometheusCollector struct {
	// Connection metrics
	connectionsTotal   prometheus.Counter
	connectionsActive  prometheus.Gauge
	tlsConnectionTotal prometheus.Counter

	// Authentication metrics
	authAttemptsTotal *prometheus.CounterVec

	// Command metrics
	commandsTotal *prometheus.CounterVec

	// Message metrics
	messagesRetrievedTotal *prometheus.CounterVec
	messagesDeletedTotal   *prometheus.CounterVec
	messagesListedTotal    *prometheus.CounterVec
	messagesSizeBytes      prometheus.Histogram
}

// NewPrometheusCollector creates a new PrometheusCollector with all metrics registered.
func NewPrometheusCollector(reg prometheus.Registerer) *PrometheusCollector {
	c := &PrometheusCollector{
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pop3d_connections_total",
			Help: "Total number of POP3 connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "pop3d_connections_active",
			Help: "Number of currently active POP3 connections.",
		}),
		tlsConnectionTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pop3d_tls_connections_total",
			Help: "Total number of TLS connections established.",
		}),

		authAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pop3d_auth_attempts_total",
			Help: "Total number of authentication attempts.",
		}, []string{"domain", "result"}),

		commandsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pop3d_commands_total",
			Help: "Total number of POP3 commands processed.",
		}, []string{"command"}),

		messagesRetrievedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pop3d_messages_retrieved_total",
			Help: "Total number of messages retrieved.",
		}, []string{"user_domain"}),
		messagesDeletedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pop3d_messages_deleted_total",
			Help: "Total number of messages marked for deletion.",
		}, []string{"user_domain"}),
		messagesListedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pop3d_messages_listed_total",
			Help: "Total number of message list operations.",
		}, []string{"user_domain"}),
		messagesSizeBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "pop3d_messages_size_bytes",
			Help:    "Size of retrieved messages in bytes.",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 26214400, 52428800},
		}),
	}

	// Register all metrics
	reg.MustRegister(
		c.connectionsTotal,
		c.connectionsActive,
		c.tlsConnectionTotal,
		c.authAttemptsTotal,
		c.commandsTotal,
		c.messagesRetrievedTotal,
		c.messagesDeletedTotal,
		c.messagesListedTotal,
		c.messagesSizeBytes,
	)

	return c
}

// ConnectionOpened increments the connection counter and active gauge.
func (c *PrometheusCollector) ConnectionOpened() {
	c.connectionsTotal.Inc()
	c.connectionsActive.Inc()
}

// ConnectionClosed decrements the active connections gauge.
func (c *PrometheusCollector) ConnectionClosed() {
	c.connectionsActive.Dec()
}

// TLSConnectionEstablished increments the TLS connection counter.
func (c *PrometheusCollector) TLSConnectionEstablished() {
	c.tlsConnectionTotal.Inc()
}

// AuthAttempt increments the authentication attempts counter.
func (c *PrometheusCollector) AuthAttempt(authDomain string, success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	c.authAttemptsTotal.WithLabelValues(authDomain, result).Inc()
}

// CommandProcessed increments the command counter.
func (c *PrometheusCollector) CommandProcessed(command string) {
	c.commandsTotal.WithLabelValues(command).Inc()
}

// MessageRetrieved increments the message retrieved counter and observes message size.
func (c *PrometheusCollector) MessageRetrieved(userDomain string, sizeBytes int64) {
	c.messagesRetrievedTotal.WithLabelValues(userDomain).Inc()
	c.messagesSizeBytes.Observe(float64(sizeBytes))
}

// MessageDeleted increments the message deleted counter.
func (c *PrometheusCollector) MessageDeleted(userDomain string) {
	c.messagesDeletedTotal.WithLabelValues(userDomain).Inc()
}

// MessageListed increments the message listed counter.
func (c *PrometheusCollector) MessageListed(userDomain string) {
	c.messagesListedTotal.WithLabelValues(userDomain).Inc()
}
