package smtp

import (
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/infodancer/maildancer/internal/smtpd/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestSubprocessMetricsEndToEnd drives the real parent path -- spawnHandler
// forking a child, passing the connection as fd 3 and the metrics pipe as fd 4,
// then the reaper draining the child's report and aggregating it -- and asserts
// the child's series actually reach the parent's registry (the surface
// promhttp serves). This is the end-to-end coverage whose absence let smtpd
// ship with metrics hardwired to a no-op sink (#170/#173): if fd 4 were not
// wired, the reaper not draining, or the collector not aggregated, no smtpd_*
// series would appear here.
//
// The child is a stand-in (testdata/metricshelper) rather than the real
// protocol-handler, because a real SMTP session needs a running session-manager
// (see integration_test.go). The helper exercises the real child-side metrics
// functions (NewHandlerCollector, WriteReport) over the real inherited fd, so
// the fork/exec + pipe + aggregation contract is covered exactly.
func TestSubprocessMetricsEndToEnd(t *testing.T) {
	helper := buildMetricsHelper(t)

	reg := prometheus.NewRegistry()
	pm := metrics.NewParentMetrics(reg)

	cfg := config.Default()
	srv := NewSubprocessServer(cfg, helper, "unused-config-path", pm, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// A real TCP connection, because spawnHandler requires a *net.TCPConn to dup
	// its fd for the child.
	serverConn := realTCPConn(t)

	srv.spawnHandler(serverConn, config.ListenerConfig{Address: "127.0.0.1:0", Mode: config.ModeSmtp})

	// The reaper runs asynchronously. Poll until it has fully completed, which
	// the active gauge returning to zero proves (it is decremented after Wait).
	waitFor(t, 5*time.Second, func() bool {
		return gaugeValue(t, reg, "smtpd_connections_active") == 0 &&
			counterValue(t, reg, "smtpd_connections_total") == 1
	})

	// Parent-owned lifecycle series, maintained by the parent from spawn/reap.
	if got := counterValue(t, reg, "smtpd_connections_total"); got != 1 {
		t.Errorf("smtpd_connections_total = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "smtpd_connections_active"); got != 0 {
		t.Errorf("smtpd_connections_active = %v, want 0 after reap", got)
	}

	// Child-reported series, aggregated from the report shipped over fd 4.
	if got := labeledCounter(t, reg, "smtpd_commands_total", "command", "EHLO"); got != 1 {
		t.Errorf("smtpd_commands_total{command=EHLO} = %v, want 1", got)
	}
	if got := labeledCounter(t, reg, "smtpd_commands_total", "command", "MAIL"); got != 1 {
		t.Errorf("smtpd_commands_total{command=MAIL} = %v, want 1", got)
	}
	if got := labeledCounter(t, reg, "smtpd_messages_received_total", "recipient_domain", "example.com"); got != 1 {
		t.Errorf("smtpd_messages_received_total{recipient_domain=example.com} = %v, want 1", got)
	}

	// No decode failures on the happy path.
	if got := labeledCounter(t, reg, "smtpd_handler_failures_total", "reason", "metrics_decode"); got != 0 {
		t.Errorf("smtpd_handler_failures_total{reason=metrics_decode} = %v, want 0", got)
	}

	// The child also recorded connection events (it reuses the full collector),
	// but the parent owns those families and must not double-count: gathering
	// would error on a duplicate family if the aggregator failed to skip them.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("registry gather failed (duplicate family?): %v", err)
	}
}

// buildMetricsHelper compiles the stand-in handler and returns its path.
func buildMetricsHelper(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "metricshelper")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/metricshelper")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build metrics helper: %v", err)
	}
	return out
}

// realTCPConn returns a live server-side *net.TCPConn from a loopback dial.
func realTCPConn(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	dialed := make(chan net.Conn, 1)
	go func() {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			dialed <- nil
			return
		}
		dialed <- c
	}()

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	clientConn := <-dialed
	if clientConn == nil {
		t.Fatal("dial failed")
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	tcp, ok := accepted.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted conn is %T, want *net.TCPConn", accepted)
	}
	return tcp
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// findFamily returns the named metric family from a gather, or nil.
func findFamily(t *testing.T, g prometheus.Gatherer, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

func counterValue(t *testing.T, g prometheus.Gatherer, name string) float64 {
	t.Helper()
	mf := findFamily(t, g, name)
	if mf == nil || len(mf.GetMetric()) != 1 {
		return 0
	}
	return mf.GetMetric()[0].GetCounter().GetValue()
}

func gaugeValue(t *testing.T, g prometheus.Gatherer, name string) float64 {
	t.Helper()
	mf := findFamily(t, g, name)
	if mf == nil || len(mf.GetMetric()) != 1 {
		return 0
	}
	return mf.GetMetric()[0].GetGauge().GetValue()
}

// labeledCounter returns the value of a counter series selected by one label.
func labeledCounter(t *testing.T, g prometheus.Gatherer, name, label, value string) float64 {
	t.Helper()
	mf := findFamily(t, g, name)
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == label && lp.GetValue() == value {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}
