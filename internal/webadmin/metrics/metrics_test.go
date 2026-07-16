package metrics_test

import (
	"testing"

	"github.com/infodancer/maildancer/internal/webadmin/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRegister(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
}

func TestAdminAuthAttempts(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.AdminAuthAttempts.WithLabelValues("success").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findCounterValue(t, mfs, "webadmin_admin_auth_attempts_total", map[string]string{"status": "success"})
	if val != 1 {
		t.Errorf("expected counter value 1, got %v", val)
	}
}

func TestAdminOperations(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.AdminOperations.WithLabelValues("create_user", "example.com").Inc()
	metrics.AdminOperations.WithLabelValues("create_user", "example.com").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findCounterValue(t, mfs, "webadmin_admin_operations_total", map[string]string{"operation": "create_user", "domain": "example.com"})
	if val != 2 {
		t.Errorf("expected counter value 2, got %v", val)
	}
}

func TestDomainCount(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.DomainCount.Set(5)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findGaugeValue(t, mfs, "webadmin_domain_count", nil)
	if val != 5 {
		t.Errorf("expected gauge value 5, got %v", val)
	}
}

func TestUserCount(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.UserCount.WithLabelValues("example.com").Set(42)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findGaugeValue(t, mfs, "webadmin_user_count", map[string]string{"domain": "example.com"})
	if val != 42 {
		t.Errorf("expected gauge value 42, got %v", val)
	}
}

func TestKeyOperations(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.KeyOperations.WithLabelValues("generate", "domain").Inc()
	metrics.KeyOperations.WithLabelValues("delete", "user").Inc()
	metrics.KeyOperations.WithLabelValues("delete", "user").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	v1 := findCounterValue(t, mfs, "webadmin_key_operations_total", map[string]string{"operation": "generate", "scope": "domain"})
	if v1 != 1 {
		t.Errorf("expected generate/domain counter 1, got %v", v1)
	}

	v2 := findCounterValue(t, mfs, "webadmin_key_operations_total", map[string]string{"operation": "delete", "scope": "user"})
	if v2 != 2 {
		t.Errorf("expected delete/user counter 2, got %v", v2)
	}
}

func TestAuditLogEntries(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.AuditLogEntries.WithLabelValues("login").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findCounterValue(t, mfs, "webadmin_audit_log_entries_total", map[string]string{"operation": "login"})
	if val != 1 {
		t.Errorf("expected counter value 1, got %v", val)
	}
}

func TestDomainPermDrift(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.DomainPermDrift.WithLabelValues("example.com").Set(3)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findGaugeValue(t, mfs, "webadmin_domain_perm_drift", map[string]string{"domain": "example.com"})
	if val != 3 {
		t.Errorf("expected gauge value 3, got %v", val)
	}
}

func TestPermCheckLastRun(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	metrics.PermCheckLastRun.SetToCurrentTime()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather returned error: %v", err)
	}

	val := findGaugeValue(t, mfs, "webadmin_perm_check_last_run_timestamp_seconds", nil)
	if val <= 0 {
		t.Errorf("expected a positive unix timestamp, got %v", val)
	}
}

func TestRegisterTwice(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	if err := metrics.Register(reg1); err != nil {
		t.Fatalf("first Register returned error: %v", err)
	}

	reg2 := prometheus.NewRegistry()
	if err := metrics.Register(reg2); err != nil {
		t.Fatalf("second Register returned error: %v", err)
	}
}

// findCounterValue finds a counter metric by name and label set and returns its value.
func findCounterValue(t *testing.T, mfs []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Errorf("metric %q with labels %v not found", name, labels)
	return 0
}

// findGaugeValue finds a gauge metric by name and optional label set and returns its value.
func findGaugeValue(t *testing.T, mfs []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Errorf("metric %q with labels %v not found", name, labels)
	return 0
}

// labelsMatch returns true when all entries in want are present in got.
func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	m := make(map[string]string, len(got))
	for _, lp := range got {
		m[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if m[k] != v {
			return false
		}
	}
	return true
}
