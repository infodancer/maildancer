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
	messagesFetchedTotal  *prometheus.CounterVec
	messagesStoredTotal   *prometheus.CounterVec
	messagesExpungedTotal *prometheus.CounterVec
	messagesSizeBytes     prometheus.Histogram

	// Mailbox metrics
	foldersSelectedTotal *prometheus.CounterVec
}

// NewPrometheusCollector creates a new PrometheusCollector with all metrics registered.
func NewPrometheusCollector(reg prometheus.Registerer) *PrometheusCollector {
	c := &PrometheusCollector{
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "imapd_connections_total",
			Help: "Total number of IMAP connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "imapd_connections_active",
			Help: "Number of currently active IMAP connections.",
		}),
		tlsConnectionTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "imapd_tls_connections_total",
			Help: "Total number of TLS connections established.",
		}),

		authAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_auth_attempts_total",
			Help: "Total number of authentication attempts.",
		}, []string{"domain", "result"}),

		commandsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_commands_total",
			Help: "Total number of IMAP commands processed.",
		}, []string{"command"}),

		messagesFetchedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_messages_fetched_total",
			Help: "Total number of messages fetched.",
		}, []string{"user_domain"}),
		messagesStoredTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_messages_stored_total",
			Help: "Total number of messages stored (APPENDed).",
		}, []string{"user_domain"}),
		messagesExpungedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_messages_expunged_total",
			Help: "Total number of messages expunged.",
		}, []string{"user_domain"}),
		messagesSizeBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "imapd_messages_size_bytes",
			Help:    "Size of fetched messages in bytes.",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 26214400, 52428800},
		}),

		foldersSelectedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imapd_folders_selected_total",
			Help: "Total number of folder SELECT/EXAMINE operations.",
		}, []string{"user_domain"}),
	}

	// Register all metrics
	reg.MustRegister(
		c.connectionsTotal,
		c.connectionsActive,
		c.tlsConnectionTotal,
		c.authAttemptsTotal,
		c.commandsTotal,
		c.messagesFetchedTotal,
		c.messagesStoredTotal,
		c.messagesExpungedTotal,
		c.messagesSizeBytes,
		c.foldersSelectedTotal,
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

// MessageFetched increments the message fetched counter and observes message size.
func (c *PrometheusCollector) MessageFetched(userDomain string, sizeBytes int64) {
	c.messagesFetchedTotal.WithLabelValues(userDomain).Inc()
	c.messagesSizeBytes.Observe(float64(sizeBytes))
}

// MessageStored increments the message stored counter.
func (c *PrometheusCollector) MessageStored(userDomain string) {
	c.messagesStoredTotal.WithLabelValues(userDomain).Inc()
}

// MessageExpunged increments the message expunged counter.
func (c *PrometheusCollector) MessageExpunged(userDomain string) {
	c.messagesExpungedTotal.WithLabelValues(userDomain).Inc()
}

// FolderSelected increments the folder selected counter.
func (c *PrometheusCollector) FolderSelected(userDomain string) {
	c.foldersSelectedTotal.WithLabelValues(userDomain).Inc()
}
