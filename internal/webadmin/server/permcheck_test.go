package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/metrics"
)

// sweepTestPaths mirrors the split config/data layout the sweep runs against
// in production.
func sweepTestPaths(t *testing.T) admin.Paths {
	t.Helper()
	root := t.TempDir()
	p := admin.Paths{
		Config: filepath.Join(root, "config"),
		Data:   filepath.Join(root, "data"),
	}
	if err := os.MkdirAll(p.Config, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Data, 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSweepPermDrift: a sweep over a fixed tree publishes a zero drift gauge
// for the domain, induced mode drift raises it to the drifted path count, and
// the last-run timestamp is stamped on every completed sweep.
func TestSweepPermDrift(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	p := sweepTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatalf("FixDomain: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sweepPermDrift(p, logger)
	if got := gaugeValue(t, reg, "webadmin_domain_perm_drift", map[string]string{"domain": "example.com"}); got != 0 {
		t.Errorf("drift gauge after fix = %v, want 0", got)
	}
	if ts := gaugeValue(t, reg, "webadmin_perm_check_last_run_timestamp_seconds", nil); ts <= 0 {
		t.Errorf("last-run timestamp = %v, want > 0", ts)
	}

	// Induce mode drift on one config file; the gauge tracks the count.
	configToml := filepath.Join(p.Config, "example.com", "config.toml")
	if err := os.Chmod(configToml, 0o750); err != nil {
		t.Fatal(err)
	}
	sweepPermDrift(p, logger)
	if got := gaugeValue(t, reg, "webadmin_domain_perm_drift", map[string]string{"domain": "example.com"}); got != 1 {
		t.Errorf("drift gauge after chmod = %v, want 1", got)
	}

	// Repair; the gauge returns to zero on the next sweep.
	if _, err := p.FixDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	sweepPermDrift(p, logger)
	if got := gaugeValue(t, reg, "webadmin_domain_perm_drift", map[string]string{"domain": "example.com"}); got != 0 {
		t.Errorf("drift gauge after repair = %v, want 0", got)
	}
}

// TestSweepPermDrift_EmptyTree: a sweep over a tree with no domains completes
// (stamping the timestamp) without publishing any per-domain series.
func TestSweepPermDrift_EmptyTree(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	p := sweepTestPaths(t)
	sweepPermDrift(p, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "webadmin_domain_perm_drift" && len(mf.GetMetric()) > 0 {
			t.Errorf("expected no per-domain drift series, got %d", len(mf.GetMetric()))
		}
	}
	if ts := gaugeValue(t, reg, "webadmin_perm_check_last_run_timestamp_seconds", nil); ts <= 0 {
		t.Errorf("last-run timestamp = %v, want > 0", ts)
	}
}

// gaugeValue gathers reg and returns the named gauge's value for the label
// set, failing the test when the series is absent.
func gaugeValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if gaugeLabelsMatch(m.GetLabel(), labels) {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Errorf("metric %q with labels %v not found", name, labels)
	return -1
}

func gaugeLabelsMatch(got []*dto.LabelPair, want map[string]string) bool {
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
