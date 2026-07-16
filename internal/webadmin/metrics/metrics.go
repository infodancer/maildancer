package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// AdminAuthAttempts counts login attempts. Labels: status ("success"/"failure")
	AdminAuthAttempts *prometheus.CounterVec

	// AdminOperations counts admin operations. Labels: operation, domain
	AdminOperations *prometheus.CounterVec

	// DomainCount tracks total number of domains (gauge)
	DomainCount prometheus.Gauge

	// UserCount tracks users per domain. Labels: domain
	UserCount *prometheus.GaugeVec

	// KeyOperations counts key operations. Labels: operation ("generate"/"delete"), scope ("domain"/"user")
	KeyOperations *prometheus.CounterVec

	// AuditLogEntries counts audit log entries. Labels: operation
	AuditLogEntries *prometheus.CounterVec

	// DomainPermDrift tracks the number of paths drifted from the permission
	// security model per domain (gauge, set by the periodic sweep). Labels: domain
	DomainPermDrift *prometheus.GaugeVec

	// PermCheckLastRun is the unix timestamp of the last completed
	// permission-drift sweep (gauge).
	PermCheckLastRun prometheus.Gauge
)

// Register initializes and registers all metrics with the given registerer.
// Safe to call multiple times with different registerers (e.g., in tests).
func Register(reg prometheus.Registerer) error {
	AdminAuthAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webadmin_admin_auth_attempts_total",
			Help: "Total number of admin authentication attempts.",
		},
		[]string{"status"},
	)

	AdminOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webadmin_admin_operations_total",
			Help: "Total number of admin operations performed.",
		},
		[]string{"operation", "domain"},
	)

	DomainCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "webadmin_domain_count",
		Help: "Current total number of domains.",
	})

	UserCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "webadmin_user_count",
			Help: "Current number of users per domain.",
		},
		[]string{"domain"},
	)

	KeyOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webadmin_key_operations_total",
			Help: "Total number of key operations performed.",
		},
		[]string{"operation", "scope"},
	)

	AuditLogEntries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webadmin_audit_log_entries_total",
			Help: "Total number of audit log entries recorded.",
		},
		[]string{"operation"},
	)

	DomainPermDrift = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "webadmin_domain_perm_drift",
			Help: "Number of paths drifted from the permission security model per domain.",
		},
		[]string{"domain"},
	)

	PermCheckLastRun = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "webadmin_perm_check_last_run_timestamp_seconds",
		Help: "Unix timestamp of the last completed permission-drift sweep.",
	})

	for _, c := range []prometheus.Collector{
		AdminAuthAttempts,
		AdminOperations,
		DomainCount,
		UserCount,
		KeyOperations,
		AuditLogEntries,
		DomainPermDrift,
		PermCheckLastRun,
	} {
		if err := reg.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) {
				return err
			}
			// Collector already registered (e.g., in tests) -- this is fine.
		}
	}

	return nil
}
