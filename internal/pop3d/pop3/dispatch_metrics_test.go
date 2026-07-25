package pop3_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/pop3d/pop3"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestDispatcherMetricsEndToEnd drives the real parent path -- the dispatcher
// forking a child per connection, passing the metrics pipe as fd 4, and the
// reaper draining the child's report into the aggregate -- and asserts the
// child's series actually reach the dispatcher's registry (the surface
// promhttp serves). This is the end-to-end coverage whose absence let smtpd
// ship with metrics hardwired to a no-op sink (#170/#173).
//
// The child is a stand-in (testdata/metricshelper) rather than the real
// protocol-handler, because a real POP3 session needs a running
// session-manager. The helper exercises the real child-side metrics functions
// (NewHandlerCollector, procmetrics.WriteReport over ChildReportPipe), so the
// fork/exec + pipe + aggregation contract is covered exactly.
func TestDispatcherMetricsEndToEnd(t *testing.T) {
	helper := buildPop3dTestHelper(t, "metricshelper")

	reg := prometheus.NewRegistry()
	pm := metrics.NewParentMetrics(reg)

	addr := freeTestPort(t)
	cfg := config.Default()
	cfg.Hostname = "metrics.local"
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModePop3}}

	dispatcher, err := pop3.NewDispatcher(pop3.DispatcherConfig{
		Config:     cfg,
		ExecPath:   helper,
		ConfigPath: "unused-config-path",
		Metrics:    pm,
		Logger:     dispatcherTestLogger(t),
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dispatcher.Run(ctx) }()

	conn := dialRetry(t, addr)
	defer conn.Close()

	// The reaper runs asynchronously. Poll until it has fully completed,
	// which the active gauge returning to zero proves (it is decremented
	// after Wait).
	waitFor(t, 5*time.Second, func() bool {
		return connectionSettled(t, reg, "pop3d")
	})

	// Child-reported series, aggregated from the report shipped over fd 4.
	if got := labeledCounter(t, reg, "pop3d_commands_total", "command", "USER"); got != 1 {
		t.Errorf("pop3d_commands_total{command=USER} = %v, want 1", got)
	}
	if got := labeledCounter(t, reg, "pop3d_commands_total", "command", "RETR"); got != 1 {
		t.Errorf("pop3d_commands_total{command=RETR} = %v, want 1", got)
	}
	if got := labeledCounter(t, reg, "pop3d_messages_retrieved_total", "user_domain", "example.com"); got != 1 {
		t.Errorf("pop3d_messages_retrieved_total{user_domain=example.com} = %v, want 1", got)
	}

	// No decode failures on the happy path.
	if got := labeledCounter(t, reg, "pop3d_handler_failures_total", "reason", "metrics_decode"); got != 0 {
		t.Errorf("pop3d_handler_failures_total{reason=metrics_decode} = %v, want 0", got)
	}
	if got := labeledCounter(t, reg, "pop3d_handler_failures_total", "reason", "empty_report"); got != 0 {
		t.Errorf("pop3d_handler_failures_total{reason=empty_report} = %v, want 0 (handler exited without writing its report)", got)
	}

	// The child also recorded connection events (it reuses the full
	// collector), but the parent owns those families and must not
	// double-count: gathering would error on a duplicate family if the
	// aggregator failed to skip them.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("registry gather failed (duplicate family?): %v", err)
	}
	if got := counterValue(t, reg, "pop3d_connections_total"); got != 1 {
		t.Errorf("pop3d_connections_total = %v, want 1 (child's copy must be dropped)", got)
	}
}

// TestDispatcherCountsChildThatDiesWithoutReport pins the #191 flake
// signature end-to-end: a handler that exits without writing its fd-4 report
// must surface as handler_failures_total{reason=empty_report}, not as a
// silent success with zero child series -- which is what the flake looked
// like before the empty report became a counted failure.
func TestDispatcherCountsChildThatDiesWithoutReport(t *testing.T) {
	helper := buildPop3dTestHelper(t, "reportlesshelper")

	reg := prometheus.NewRegistry()
	pm := metrics.NewParentMetrics(reg)

	addr := freeTestPort(t)
	cfg := config.Default()
	cfg.Hostname = "metrics.local"
	cfg.Listeners = []config.ListenerConfig{{Address: addr, Mode: config.ModePop3}}

	dispatcher, err := pop3.NewDispatcher(pop3.DispatcherConfig{
		Config:     cfg,
		ExecPath:   helper,
		ConfigPath: "unused-config-path",
		Metrics:    pm,
		Logger:     dispatcherTestLogger(t),
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dispatcher.Run(ctx) }()

	conn := dialRetry(t, addr)
	defer conn.Close()

	waitFor(t, 5*time.Second, func() bool {
		return connectionSettled(t, reg, "pop3d")
	})

	if got := labeledCounter(t, reg, "pop3d_handler_failures_total", "reason", "empty_report"); got != 1 {
		t.Errorf("pop3d_handler_failures_total{reason=empty_report} = %v, want 1", got)
	}
	if got := labeledCounter(t, reg, "pop3d_handler_failures_total", "reason", "metrics_decode"); got != 0 {
		t.Errorf("pop3d_handler_failures_total{reason=metrics_decode} = %v, want 0", got)
	}
}

// buildPop3dTestHelper compiles a stand-in handler from testdata and returns
// its path.
func buildPop3dTestHelper(t *testing.T, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, "./testdata/"+name)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build %s: %v", name, err)
	}
	return out
}

// freeTestPort returns a free loopback address.
func freeTestPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
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

// connectionSettled reports whether one connection has been fully handled --
// spawned and reaped -- reading both series from a SINGLE gather.
//
// Two separate reads are not equivalent and were the cause of #215: an
// `active == 0` sampled before the connection was accepted combines with a
// `total == 1` sampled after the spawn, so the condition passes while the child
// is still running. connfork drains the handler's report before OnConnEnd, so a
// genuinely settled state is what makes the report assertions that follow
// reliable; a spliced one is not.
func connectionSettled(t *testing.T, g prometheus.Gatherer, namespace string) bool {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var active, total float64
	for _, mf := range mfs {
		metrics := mf.GetMetric()
		if len(metrics) != 1 {
			continue
		}
		switch mf.GetName() {
		case namespace + "_connections_active":
			active = metrics[0].GetGauge().GetValue()
		case namespace + "_connections_total":
			total = metrics[0].GetCounter().GetValue()
		}
	}
	return active == 0 && total == 1
}

func counterValue(t *testing.T, g prometheus.Gatherer, name string) float64 {
	t.Helper()
	mf := findFamily(t, g, name)
	if mf == nil || len(mf.GetMetric()) != 1 {
		return 0
	}
	return mf.GetMetric()[0].GetCounter().GetValue()
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

// dispatcherTestLogger records dispatcher output (down to the Debug-level
// reaper lines) and replays it if the test fails. The #191 flake was
// undiagnosable with the logs discarded: the one line that says why a child
// exited without a report is logged at Debug by the reaper.
func dispatcherTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	buf := &lockedBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			if out := buf.String(); out != "" {
				t.Logf("dispatcher log:\n%s", out)
			}
		}
	})
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// lockedBuffer makes the log buffer safe for the dispatcher's reaper
// goroutines, which may still be writing at cleanup time.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
