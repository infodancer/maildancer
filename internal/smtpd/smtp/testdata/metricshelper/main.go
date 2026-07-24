// Command metricshelper is a stand-in protocol-handler used by the smtpd
// subprocess metrics end-to-end test. The real handler needs a running
// session-manager to run an SMTP session, so this helper skips the session and
// exercises only the metrics contract the parent depends on: it records a fixed
// set of events into the real child-side collector and ships the report to the
// parent over fd 4, exactly as cmd/smtpd/handler.go does at session end.
//
// It is built (by explicit path, since the go tool ignores testdata) and
// spawned by TestSubprocessMetricsEndToEnd in the parent package; it is not part
// of any normal build.
package main

import (
	"os"

	"github.com/infodancer/maildancer/internal/smtpd/metrics"
)

// metricsFD mirrors cmd/smtpd.metricsFD: the parent passes the metrics-report
// pipe as the second ExtraFiles entry, which the OS maps to fd 4 in the child.
const metricsFD = 4

func main() {
	// fd 3 is the connection socket; this helper does not run a session, so it
	// simply ignores it and lets exit close it.

	c, reg := metrics.NewHandlerCollector()

	// A fixed, checkable session's worth of activity. The connection events are
	// recorded too (the real child does, via the shared collector) so the test
	// can prove the parent drops the parent-owned connection families.
	c.ConnectionOpened()
	c.CommandProcessed("EHLO")
	c.CommandProcessed("MAIL")
	c.MessageReceived("example.com", 1234)
	c.ConnectionClosed()

	reportFile := os.NewFile(uintptr(metricsFD), "smtp-metrics")
	if reportFile == nil {
		os.Exit(1)
	}
	if err := metrics.WriteReport(reportFile, reg); err != nil {
		os.Exit(1)
	}
	_ = reportFile.Close()
}
