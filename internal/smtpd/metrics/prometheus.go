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

	// Message metrics
	messagesReceivedTotal *prometheus.CounterVec
	messagesRejectedTotal *prometheus.CounterVec
	messagesSizeBytes     prometheus.Histogram

	// Authentication metrics
	authAttemptsTotal *prometheus.CounterVec

	// Command metrics
	commandsTotal *prometheus.CounterVec

	// Delivery metrics
	deliveriesTotal *prometheus.CounterVec

	// Anti-spam metrics
	spfChecksTotal   *prometheus.CounterVec
	dkimChecksTotal  *prometheus.CounterVec
	dmarcChecksTotal *prometheus.CounterVec
	rblHitsTotal     *prometheus.CounterVec
}

// NewPrometheusCollector creates a new PrometheusCollector with all metrics registered.
func NewPrometheusCollector(reg prometheus.Registerer) *PrometheusCollector {
	c := &PrometheusCollector{
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "smtpd_connections_total",
			Help: "Total number of SMTP connections opened.",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "smtpd_connections_active",
			Help: "Number of currently active SMTP connections.",
		}),
		tlsConnectionTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "smtpd_tls_connections_total",
			Help: "Total number of TLS connections established.",
		}),

		messagesReceivedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_messages_received_total",
			Help: "Total number of messages received.",
		}, []string{"recipient_domain"}),
		messagesRejectedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_messages_rejected_total",
			Help: "Total number of messages rejected.",
		}, []string{"recipient_domain", "reason"}),
		messagesSizeBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtpd_messages_size_bytes",
			Help:    "Size of received messages in bytes.",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 26214400, 52428800},
		}),

		authAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_auth_attempts_total",
			Help: "Total number of authentication attempts.",
		}, []string{"domain", "result"}),

		commandsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_commands_total",
			Help: "Total number of SMTP commands processed.",
		}, []string{"command"}),

		deliveriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_deliveries_total",
			Help: "Total number of delivery attempts.",
		}, []string{"recipient_domain", "result"}),

		spfChecksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_spf_checks_total",
			Help: "Total number of SPF checks performed.",
		}, []string{"sender_domain", "result"}),
		dkimChecksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_dkim_checks_total",
			Help: "Total number of DKIM checks performed.",
		}, []string{"sender_domain", "result"}),
		dmarcChecksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_dmarc_checks_total",
			Help: "Total number of DMARC checks performed.",
		}, []string{"sender_domain", "result"}),
		rblHitsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smtpd_rbl_hits_total",
			Help: "Total number of RBL/DNSBL hits.",
		}, []string{"list"}),
	}

	// Register all metrics
	reg.MustRegister(
		c.connectionsTotal,
		c.connectionsActive,
		c.tlsConnectionTotal,
		c.messagesReceivedTotal,
		c.messagesRejectedTotal,
		c.messagesSizeBytes,
		c.authAttemptsTotal,
		c.commandsTotal,
		c.deliveriesTotal,
		c.spfChecksTotal,
		c.dkimChecksTotal,
		c.dmarcChecksTotal,
		c.rblHitsTotal,
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

// MessageReceived increments the message received counter and observes message size.
func (c *PrometheusCollector) MessageReceived(recipientDomain string, sizeBytes int64) {
	c.messagesReceivedTotal.WithLabelValues(recipientDomain).Inc()
	c.messagesSizeBytes.Observe(float64(sizeBytes))
}

// MessageRejected increments the message rejected counter.
func (c *PrometheusCollector) MessageRejected(recipientDomain string, reason string) {
	c.messagesRejectedTotal.WithLabelValues(recipientDomain, reason).Inc()
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

// DeliveryCompleted increments the delivery counter.
func (c *PrometheusCollector) DeliveryCompleted(recipientDomain string, result string) {
	c.deliveriesTotal.WithLabelValues(recipientDomain, result).Inc()
}

// SPFCheckCompleted increments the SPF check counter.
func (c *PrometheusCollector) SPFCheckCompleted(senderDomain string, result string) {
	c.spfChecksTotal.WithLabelValues(senderDomain, result).Inc()
}

// DKIMCheckCompleted increments the DKIM check counter.
func (c *PrometheusCollector) DKIMCheckCompleted(senderDomain string, result string) {
	c.dkimChecksTotal.WithLabelValues(senderDomain, result).Inc()
}

// DMARCCheckCompleted increments the DMARC check counter.
func (c *PrometheusCollector) DMARCCheckCompleted(senderDomain string, result string) {
	c.dmarcChecksTotal.WithLabelValues(senderDomain, result).Inc()
}

// RBLHit increments the RBL hits counter.
func (c *PrometheusCollector) RBLHit(listName string) {
	c.rblHitsTotal.WithLabelValues(listName).Inc()
}
