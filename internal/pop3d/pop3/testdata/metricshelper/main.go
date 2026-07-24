// Command metricshelper is a stand-in protocol-handler used by the pop3d
// dispatcher metrics end-to-end test. The real handler needs a running
// session-manager to serve a POP3 session, so this helper skips the session
// and exercises only the metrics contract the dispatcher depends on: it
// records a fixed set of events into the real child-side collector and ships
// the report to the parent over the fd-4 pipe, exactly as cmd/pop3d/handler.go
// does at session end.
//
// It is built (by explicit path, since the go tool ignores testdata) and
// spawned by TestDispatcherMetricsEndToEnd; it is not part of any normal
// build.
package main

import (
	"os"

	"github.com/infodancer/maildancer/internal/connfork"
	"github.com/infodancer/maildancer/internal/pop3d/metrics"
	"github.com/infodancer/maildancer/internal/procmetrics"
)

func main() {
	// fd 3 is the connection socket; this helper does not run a session, so
	// it simply ignores it and lets exit close it.

	c, reg := metrics.NewHandlerCollector()

	// A fixed, checkable session's worth of activity. The connection events
	// are recorded too (the real child does, via the shared collector) so
	// the test can prove the parent drops the parent-owned connection
	// families.
	c.ConnectionOpened()
	c.CommandProcessed("USER")
	c.CommandProcessed("RETR")
	c.AuthAttempt("example.com", true)
	c.MessageRetrieved("example.com", 1234)
	c.ConnectionClosed()

	report := connfork.ChildReportPipe()
	if err := procmetrics.WriteReport(report, reg); err != nil {
		os.Exit(1)
	}
	_ = report.Close()
}
